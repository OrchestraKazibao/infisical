/* eslint-disable no-await-in-loop */
import { AxiosError } from "axios";

import { request } from "@app/lib/config/request";
import { TAppConnectionDALFactory } from "@app/services/app-connection/app-connection-dal";
import { getAzureConnectionAccessToken } from "@app/services/app-connection/azure-key-vault";
import { createConnectionQueue, RateLimitConfig } from "@app/services/connection-queue";
import { TKmsServiceFactory } from "@app/services/kms/kms-service";
import { matchesSchema } from "@app/services/secret-sync/secret-sync-fns";
import { TSecretMap } from "@app/services/secret-sync/secret-sync-types";

import { SecretSyncError } from "../secret-sync-errors";
import { GetAzureKeyVaultSecret, TAzureKeyVaultSyncWithCredentials } from "./azure-key-vault-sync-types";

const AZURE_RATE_LIMIT_CONFIG: RateLimitConfig = {
  MAX_CONCURRENT_REQUESTS: 10,
  BASE_DELAY: 1000,
  MAX_DELAY: 30000,
  MAX_RETRIES: 3,
  RATE_LIMIT_STATUS_CODES: [429, 503]
};

const { withRateLimitRetry, executeWithConcurrencyLimit } = createConnectionQueue(AZURE_RATE_LIMIT_CONFIG);

type TAzureKeyVaultSyncFactoryDeps = {
  appConnectionDAL: Pick<TAppConnectionDALFactory, "findById" | "updateById">;
  kmsService: Pick<TKmsServiceFactory, "createCipherPairWithDataKey">;
};

export const azureKeyVaultSyncFactory = ({ kmsService, appConnectionDAL }: TAzureKeyVaultSyncFactoryDeps) => {
  const $getAzureKeyVaultSecrets = async (accessToken: string, vaultBaseUrl: string, syncId: string) => {
    const paginateAzureKeyVaultSecrets = async () => {
      let result: GetAzureKeyVaultSecret[] = [];

      let currentUrl = `${vaultBaseUrl}/secrets?api-version=7.3`;

      while (currentUrl) {
        const res = await withRateLimitRetry(
          () =>
            request.get<{ value: GetAzureKeyVaultSecret[]; nextLink: string }>(currentUrl, {
              headers: {
                Authorization: `Bearer ${accessToken}`
              }
            }),
          { operation: "list-secrets", syncId }
        );

        result = result.concat(res.data.value);
        currentUrl = res.data.nextLink;
      }

      return result;
    };

    const getAzureKeyVaultSecrets = await paginateAzureKeyVaultSecrets();

    const enabledAzureKeyVaultSecrets = getAzureKeyVaultSecrets.filter((secret) => secret.attributes.enabled);

    // disabled keys to skip sending updates to
    const disabledAzureKeyVaultSecretKeys = getAzureKeyVaultSecrets
      .filter(({ attributes }) => !attributes.enabled)
      .map((getAzureKeyVaultSecret) => {
        return getAzureKeyVaultSecret.id.substring(getAzureKeyVaultSecret.id.lastIndexOf("/") + 1);
      });

    const secretResults = await executeWithConcurrencyLimit(
      enabledAzureKeyVaultSecrets,
      async (getAzureKeyVaultSecret) => {
        const lastSlashIndex = getAzureKeyVaultSecret.id.lastIndexOf("/");

        const azureKeyVaultSecret = await request.get<GetAzureKeyVaultSecret>(
          `${getAzureKeyVaultSecret.id}?api-version=7.3`,
          {
            headers: {
              Authorization: `Bearer ${accessToken}`
            }
          }
        );

        return {
          ...azureKeyVaultSecret.data,
          key: getAzureKeyVaultSecret.id.substring(lastSlashIndex + 1)
        };
      },
      { operation: "fetch-secret-details", syncId }
    );

    const failedResults = secretResults.filter(
      (result): result is PromiseRejectedResult => result.status === "rejected"
    );

    if (failedResults.length > 0) {
      throw new SecretSyncError({
        error: failedResults[0].reason,
        message: `Failed to fetch ${failedResults.length} secret(s) from Azure Key Vault`
      });
    }

    const res = secretResults
      .filter(
        (result): result is PromiseFulfilledResult<GetAzureKeyVaultSecret & { key: string }> =>
          result.status === "fulfilled"
      )
      .reduce(
        (obj, result) => ({
          ...obj,
          [result.value.key]: result.value
        }),
        {} as Record<string, GetAzureKeyVaultSecret>
      );

    return {
      vaultSecrets: res,
      disabledAzureKeyVaultSecretKeys
    };
  };

  const syncSecrets = async (secretSync: TAzureKeyVaultSyncWithCredentials, secretMap: TSecretMap) => {
    const { accessToken } = await getAzureConnectionAccessToken(secretSync.connection.id, appConnectionDAL, kmsService);

    const { vaultSecrets, disabledAzureKeyVaultSecretKeys } = await $getAzureKeyVaultSecrets(
      accessToken,
      secretSync.destinationConfig.vaultBaseUrl,
      secretSync.id
    );

    const setSecrets: {
      key: string;
      value: string;
    }[] = [];

    const deleteSecrets: string[] = [];

    Object.keys(secretMap).forEach((infisicalKey) => {
      const hyphenatedKey = infisicalKey.replaceAll("_", "-");
      if (!(hyphenatedKey in vaultSecrets)) {
        // case: secret has been created
        setSecrets.push({
          key: hyphenatedKey,
          value: secretMap[infisicalKey].value
        });
      } else if (secretMap[infisicalKey].value !== vaultSecrets[hyphenatedKey].value) {
        // case: secret has been updated
        setSecrets.push({
          key: hyphenatedKey,
          value: secretMap[infisicalKey].value
        });
      }
    });

    Object.keys(vaultSecrets).forEach((key) => {
      const underscoredKey = key.replaceAll("-", "_");
      if (!(underscoredKey in secretMap)) {
        deleteSecrets.push(key);
      }
    });

    const setSecretAzureKeyVault = async ({ key, value }: { key: string; value: string }) => {
      if (disabledAzureKeyVaultSecretKeys.includes(key)) return;

      let isSecretSet = false;
      let syncError: Error | null = null;
      let maxTries = 6;

      while (!isSecretSet && maxTries > 0) {
        try {
          await request.put(
            `${secretSync.destinationConfig.vaultBaseUrl}/secrets/${key}?api-version=7.3`,
            {
              value
            },
            {
              headers: {
                Authorization: `Bearer ${accessToken}`
              }
            }
          );

          isSecretSet = true;
        } catch (err) {
          syncError = err as Error;
          if (
            err instanceof AxiosError &&
            // eslint-disable-next-line
            err.response?.data?.error?.innererror?.code === "ObjectIsDeletedButRecoverable"
          ) {
            await request.post(
              `${secretSync.destinationConfig.vaultBaseUrl}/deletedsecrets/${key}/recover?api-version=7.3`,
              {},
              {
                headers: {
                  Authorization: `Bearer ${accessToken}`
                }
              }
            );

            await new Promise((resolve) => {
              setTimeout(resolve, 10_000);
            });
            maxTries -= 1;
          } else {
            throw err;
          }
        }
      }

      if (!isSecretSet) {
        throw new SecretSyncError({
          error: syncError,
          secretKey: key
        });
      }
    };

    const setResults = await executeWithConcurrencyLimit(
      setSecrets,
      async ({ key, value }) => {
        await setSecretAzureKeyVault({ key, value });
        return key;
      },
      { operation: "set-secrets", syncId: secretSync.id }
    );

    const failedSets = setResults.filter(
      (result): result is PromiseRejectedResult => result.status === "rejected"
    );

    if (failedSets.length > 0) {
      const firstError = failedSets[0].reason;
      throw new SecretSyncError({
        error: firstError,
        secretKey: firstError instanceof SecretSyncError ? firstError.secretKey : undefined
      });
    }

    if (secretSync.syncOptions.disableSecretDeletion) return;

    const filteredDeleteSecrets = deleteSecrets.filter(
      (secret) =>
        matchesSchema(secret, secretSync.environment?.slug || "", secretSync.syncOptions.keySchema) &&
        !setSecrets.find((setSecret) => setSecret.key === secret)
    );

    const deleteResults = await executeWithConcurrencyLimit(
      filteredDeleteSecrets,
      async (deleteSecretKey) => {
        await request.delete(
          `${secretSync.destinationConfig.vaultBaseUrl}/secrets/${deleteSecretKey}?api-version=7.3`,
          {
            headers: {
              Authorization: `Bearer ${accessToken}`
            }
          }
        );
        return deleteSecretKey;
      },
      { operation: "delete-secrets", syncId: secretSync.id }
    );

    const failedDeletes = deleteResults.filter(
      (result): result is PromiseRejectedResult => result.status === "rejected"
    );

    if (failedDeletes.length > 0) {
      throw new SecretSyncError({
        error: failedDeletes[0].reason
      });
    }
  };

  const removeSecrets = async (secretSync: TAzureKeyVaultSyncWithCredentials, secretMap: TSecretMap) => {
    const { accessToken } = await getAzureConnectionAccessToken(secretSync.connection.id, appConnectionDAL, kmsService);

    const { vaultSecrets, disabledAzureKeyVaultSecretKeys } = await $getAzureKeyVaultSecrets(
      accessToken,
      secretSync.destinationConfig.vaultBaseUrl,
      secretSync.id
    );

    const secretsToRemove = Object.entries(vaultSecrets)
      .filter(([key]) => {
        const underscoredKey = key.replaceAll("-", "_");
        return underscoredKey in secretMap && !disabledAzureKeyVaultSecretKeys.includes(underscoredKey);
      })
      .map(([key]) => key);

    const removeResults = await executeWithConcurrencyLimit(
      secretsToRemove,
      async (key) => {
        await request.delete(`${secretSync.destinationConfig.vaultBaseUrl}/secrets/${key}?api-version=7.3`, {
          headers: {
            Authorization: `Bearer ${accessToken}`
          }
        });
        return key;
      },
      { operation: "remove-secrets", syncId: secretSync.id }
    );

    const failedRemoves = removeResults.filter(
      (result): result is PromiseRejectedResult => result.status === "rejected"
    );

    if (failedRemoves.length > 0) {
      throw new SecretSyncError({
        error: failedRemoves[0].reason
      });
    }
  };

  const getSecrets = async (secretSync: TAzureKeyVaultSyncWithCredentials) => {
    const { accessToken } = await getAzureConnectionAccessToken(secretSync.connection.id, appConnectionDAL, kmsService);

    const { vaultSecrets, disabledAzureKeyVaultSecretKeys } = await $getAzureKeyVaultSecrets(
      accessToken,
      secretSync.destinationConfig.vaultBaseUrl,
      secretSync.id
    );

    const secretMap: TSecretMap = {};

    Object.keys(vaultSecrets).forEach((key) => {
      if (!disabledAzureKeyVaultSecretKeys.includes(key)) {
        const underscoredKey = key.replaceAll("-", "_");
        secretMap[underscoredKey] = {
          value: vaultSecrets[key].value
        };
      }
    });

    return secretMap;
  };

  return {
    syncSecrets,
    removeSecrets,
    getSecrets
  };
};
