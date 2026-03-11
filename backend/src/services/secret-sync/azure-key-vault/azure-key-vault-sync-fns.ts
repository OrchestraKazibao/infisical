/* eslint-disable no-await-in-loop */
import { AxiosError } from "axios";

import { request } from "@app/lib/config/request";
import { logger } from "@app/lib/logger";
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
      let pageCount = 0;

      while (currentUrl) {
        pageCount += 1;
        const res = await withRateLimitRetry(
          () =>
            request.get<{ value: GetAzureKeyVaultSecret[]; nextLink: string }>(currentUrl, {
              headers: {
                Authorization: `Bearer ${accessToken}`
              }
            }),
          { operation: "list-secrets", syncId }
        );

        logger.info(
          {
            syncId,
            operation: "list-secrets",
            page: pageCount,
            secretsInPage: res.data.value.length,
            hasNextPage: !!res.data.nextLink
          },
          "AzureKeyVaultSync: Fetched secrets page from vault"
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

    logger.info(
      {
        syncId,
        operation: "fetch-vault-secrets",
        totalSecrets: getAzureKeyVaultSecrets.length,
        enabledSecrets: enabledAzureKeyVaultSecrets.length,
        disabledSecretKeys: disabledAzureKeyVaultSecretKeys
      },
      "AzureKeyVaultSync: Vault secrets fetched and classified"
    );

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

        const key = getAzureKeyVaultSecret.id.substring(lastSlashIndex + 1);
        logger.debug(
          {
            syncId,
            operation: "fetch-secret-detail",
            secretKey: key
          },
          "AzureKeyVaultSync: Fetched secret detail"
        );

        return {
          ...azureKeyVaultSecret.data,
          key
        };
      },
      { operation: "fetch-secret-details", syncId }
    );

    const failedResults = secretResults.filter(
      (result): result is PromiseRejectedResult => result.status === "rejected"
    );

    if (failedResults.length > 0) {
      logger.error(
        {
          syncId,
          operation: "fetch-secret-details",
          failedCount: failedResults.length,
          error: String(failedResults[0].reason)
        },
        "AzureKeyVaultSync: Failed to fetch secret details"
      );

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
    logger.info(
      {
        syncId: secretSync.id,
        operation: "sync-start",
        destination: "azure-key-vault",
        vaultBaseUrl: secretSync.destinationConfig.vaultBaseUrl,
        connectionId: secretSync.connection.id,
        infisicalSecretCount: Object.keys(secretMap).length,
        infisicalSecretKeys: Object.keys(secretMap),
        disableSecretDeletion: secretSync.syncOptions.disableSecretDeletion
      },
      "AzureKeyVaultSync: Starting synchronization"
    );

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

    // Track which vault keys are managed by Infisical secrets
    const managedVaultKeys = new Set<string>();

    Object.keys(secretMap).forEach((infisicalKey) => {
      const hyphenatedKey = infisicalKey.replaceAll("_", "-");
      managedVaultKeys.add(hyphenatedKey);
      if (!(hyphenatedKey in vaultSecrets)) {
        // case: secret has been created
        logger.info(
          {
            syncId: secretSync.id,
            operation: "sync-diff",
            action: "create",
            secretKey: hyphenatedKey,
            infisicalKey
          },
          "AzureKeyVaultSync: Secret marked for creation (not found in vault)"
        );
        setSecrets.push({
          key: hyphenatedKey,
          value: secretMap[infisicalKey].value
        });
      } else if (secretMap[infisicalKey].value !== vaultSecrets[hyphenatedKey].value) {
        // case: secret has been updated
        logger.info(
          {
            syncId: secretSync.id,
            operation: "sync-diff",
            action: "update",
            secretKey: hyphenatedKey,
            infisicalKey
          },
          "AzureKeyVaultSync: Secret marked for update (value differs)"
        );
        setSecrets.push({
          key: hyphenatedKey,
          value: secretMap[infisicalKey].value
        });
      } else {
        logger.debug(
          {
            syncId: secretSync.id,
            operation: "sync-diff",
            action: "unchanged",
            secretKey: hyphenatedKey,
            infisicalKey
          },
          "AzureKeyVaultSync: Secret unchanged, skipping"
        );
      }
    });

    Object.keys(vaultSecrets).forEach((key) => {
      if (!managedVaultKeys.has(key)) {
        logger.info(
          {
            syncId: secretSync.id,
            operation: "sync-diff",
            action: "delete-candidate",
            secretKey: key,
            underscoredKey
          },
          "AzureKeyVaultSync: Vault secret not found in Infisical, marked as delete candidate"
        );
        deleteSecrets.push(key);
      }
    });

    logger.info(
      {
        syncId: secretSync.id,
        operation: "sync-diff-summary",
        secretsToSet: setSecrets.length,
        secretsToSetKeys: setSecrets.map((s) => s.key),
        deleteCandidates: deleteSecrets.length,
        deleteCandidateKeys: deleteSecrets,
        vaultSecretKeys: Object.keys(vaultSecrets),
        disabledKeys: disabledAzureKeyVaultSecretKeys
      },
      "AzureKeyVaultSync: Diff computed"
    );

    const setSecretAzureKeyVault = async ({ key, value }: { key: string; value: string }) => {
      if (disabledAzureKeyVaultSecretKeys.includes(key)) {
        logger.info(
          {
            syncId: secretSync.id,
            operation: "set-secret",
            action: "skipped-disabled",
            secretKey: key
          },
          "AzureKeyVaultSync: Skipping set for disabled secret"
        );
        return;
      }

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
          logger.info(
            {
              syncId: secretSync.id,
              operation: "set-secret",
              action: "success",
              secretKey: key
            },
            "AzureKeyVaultSync: Secret set successfully"
          );
        } catch (err) {
          syncError = err as Error;
          if (
            err instanceof AxiosError &&
            // eslint-disable-next-line
            err.response?.data?.error?.innererror?.code === "ObjectIsDeletedButRecoverable"
          ) {
            logger.warn(
              {
                syncId: secretSync.id,
                operation: "set-secret",
                action: "recovering-soft-deleted",
                secretKey: key,
                remainingTries: maxTries - 1
              },
              "AzureKeyVaultSync: Secret is soft-deleted, attempting recovery"
            );

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
            logger.error(
              {
                syncId: secretSync.id,
                operation: "set-secret",
                action: "error",
                secretKey: key,
                error: err instanceof AxiosError ? err.message : String(err)
              },
              "AzureKeyVaultSync: Failed to set secret"
            );
            throw err;
          }
        }
      }

      if (!isSecretSet) {
        logger.error(
          {
            syncId: secretSync.id,
            operation: "set-secret",
            action: "exhausted-retries",
            secretKey: key
          },
          "AzureKeyVaultSync: Exhausted retries for soft-deleted secret recovery"
        );
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
      logger.error(
        {
          syncId: secretSync.id,
          operation: "set-secrets",
          failedCount: failedSets.length,
          totalCount: setSecrets.length,
          error: String(firstError)
        },
        "AzureKeyVaultSync: Failed to set secrets in vault"
      );
      throw new SecretSyncError({
        error: firstError,
        secretKey: firstError instanceof SecretSyncError ? firstError.secretKey : undefined,
        message: `Failed to set ${failedSets.length} secret(s) in Azure Key Vault`
      });
    }

    logger.info(
      {
        syncId: secretSync.id,
        operation: "set-secrets-complete",
        successCount: setSecrets.length
      },
      "AzureKeyVaultSync: All secrets set successfully"
    );

    if (secretSync.syncOptions.disableSecretDeletion) {
      logger.info(
        {
          syncId: secretSync.id,
          operation: "delete-secrets",
          action: "skipped-deletion-disabled",
          deleteCandidateCount: deleteSecrets.length
        },
        "AzureKeyVaultSync: Secret deletion is disabled, skipping deletions"
      );
      return;
    }

    const filteredDeleteSecrets = deleteSecrets.filter(
      (secret) =>
        matchesSchema(secret, secretSync.environment?.slug || "", secretSync.syncOptions.keySchema) &&
        !setSecrets.find((setSecret) => setSecret.key === secret)
    );

    logger.info(
      {
        syncId: secretSync.id,
        operation: "delete-secrets",
        action: "filtered",
        deleteCandidateCount: deleteSecrets.length,
        deleteCandidateKeys: deleteSecrets,
        filteredDeleteCount: filteredDeleteSecrets.length,
        filteredDeleteKeys: filteredDeleteSecrets,
        skippedBySchemaOrSetCount: deleteSecrets.length - filteredDeleteSecrets.length
      },
      "AzureKeyVaultSync: DELETE — Filtered deletion candidates"
    );

    const deleteResults = await executeWithConcurrencyLimit(
      filteredDeleteSecrets,
      async (deleteSecretKey) => {
        logger.warn(
          {
            syncId: secretSync.id,
            operation: "delete-secret",
            action: "deleting",
            secretKey: deleteSecretKey
          },
          "AzureKeyVaultSync: DELETE — Deleting secret from vault"
        );

        await request.delete(
          `${secretSync.destinationConfig.vaultBaseUrl}/secrets/${deleteSecretKey}?api-version=7.3`,
          {
            headers: {
              Authorization: `Bearer ${accessToken}`
            }
          }
        );

        logger.warn(
          {
            syncId: secretSync.id,
            operation: "delete-secret",
            action: "deleted",
            secretKey: deleteSecretKey
          },
          "AzureKeyVaultSync: DELETE — Secret deleted from vault"
        );

        return deleteSecretKey;
      },
      { operation: "delete-secrets", syncId: secretSync.id }
    );

    const failedDeletes = deleteResults.filter(
      (result): result is PromiseRejectedResult => result.status === "rejected"
    );

    if (failedDeletes.length > 0) {
      logger.error(
        {
          syncId: secretSync.id,
          operation: "delete-secrets",
          failedCount: failedDeletes.length,
          totalCount: filteredDeleteSecrets.length,
          error: String(failedDeletes[0].reason)
        },
        "AzureKeyVaultSync: DELETE — Failed to delete secrets from vault"
      );
      throw new SecretSyncError({
        error: failedDeletes[0].reason,
        message: `Failed to delete ${failedDeletes.length} secret(s) from Azure Key Vault`
      });
    }

    logger.info(
      {
        syncId: secretSync.id,
        operation: "sync-complete",
        secretsSet: setSecrets.length,
        secretsDeleted: filteredDeleteSecrets.length,
        secretsUnchanged: Object.keys(secretMap).length - setSecrets.length
      },
      "AzureKeyVaultSync: Synchronization completed successfully"
    );
  };

  const removeSecrets = async (secretSync: TAzureKeyVaultSyncWithCredentials, secretMap: TSecretMap) => {
    logger.info(
      {
        syncId: secretSync.id,
        operation: "remove-start",
        destination: "azure-key-vault",
        vaultBaseUrl: secretSync.destinationConfig.vaultBaseUrl,
        secretMapKeys: Object.keys(secretMap)
      },
      "AzureKeyVaultSync: Starting secret removal"
    );

    const { accessToken } = await getAzureConnectionAccessToken(secretSync.connection.id, appConnectionDAL, kmsService);

    const { vaultSecrets, disabledAzureKeyVaultSecretKeys } = await $getAzureKeyVaultSecrets(
      accessToken,
      secretSync.destinationConfig.vaultBaseUrl,
      secretSync.id
    );

    // Build a set of vault keys managed by Infisical secrets
    const managedVaultKeys = new Set<string>();
    Object.keys(secretMap).forEach((infisicalKey) => {
      managedVaultKeys.add(infisicalKey.replaceAll("_", "-"));
    });

    const secretsToRemove = Object.entries(vaultSecrets)
      .filter(([key]) => {
        return managedVaultKeys.has(key) && !disabledAzureKeyVaultSecretKeys.includes(key);
      })
      .map(([key]) => key);

    logger.info(
      {
        syncId: secretSync.id,
        operation: "remove-diff",
        vaultSecretKeys: Object.keys(vaultSecrets),
        disabledKeys: disabledAzureKeyVaultSecretKeys,
        secretsToRemoveKeys: secretsToRemove,
        secretsToRemoveCount: secretsToRemove.length
      },
      "AzureKeyVaultSync: DELETE — Computed secrets to remove"
    );

    const removeResults = await executeWithConcurrencyLimit(
      secretsToRemove,
      async (key) => {
        logger.warn(
          {
            syncId: secretSync.id,
            operation: "remove-secret",
            action: "deleting",
            secretKey: key
          },
          "AzureKeyVaultSync: DELETE — Removing secret from vault"
        );

        await request.delete(`${secretSync.destinationConfig.vaultBaseUrl}/secrets/${key}?api-version=7.3`, {
          headers: {
            Authorization: `Bearer ${accessToken}`
          }
        });

        logger.warn(
          {
            syncId: secretSync.id,
            operation: "remove-secret",
            action: "deleted",
            secretKey: key
          },
          "AzureKeyVaultSync: DELETE — Secret removed from vault"
        );

        return key;
      },
      { operation: "remove-secrets", syncId: secretSync.id }
    );

    const failedRemoves = removeResults.filter(
      (result): result is PromiseRejectedResult => result.status === "rejected"
    );

    if (failedRemoves.length > 0) {
      logger.error(
        {
          syncId: secretSync.id,
          operation: "remove-secrets",
          failedCount: failedRemoves.length,
          totalCount: secretsToRemove.length,
          error: String(failedRemoves[0].reason)
        },
        "AzureKeyVaultSync: DELETE — Failed to remove secrets from vault"
      );
      throw new SecretSyncError({
        error: failedRemoves[0].reason,
        message: `Failed to remove ${failedRemoves.length} secret(s) from Azure Key Vault`
      });
    }

    logger.info(
      {
        syncId: secretSync.id,
        operation: "remove-complete",
        removedCount: secretsToRemove.length,
        removedKeys: secretsToRemove
      },
      "AzureKeyVaultSync: Secret removal completed successfully"
    );
  };

  const getSecrets = async (secretSync: TAzureKeyVaultSyncWithCredentials) => {
    logger.info(
      {
        syncId: secretSync.id,
        operation: "get-secrets-start",
        destination: "azure-key-vault",
        vaultBaseUrl: secretSync.destinationConfig.vaultBaseUrl
      },
      "AzureKeyVaultSync: Starting secrets retrieval"
    );

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

    logger.info(
      {
        syncId: secretSync.id,
        operation: "get-secrets-complete",
        totalVaultSecrets: Object.keys(vaultSecrets).length,
        disabledSecrets: disabledAzureKeyVaultSecretKeys.length,
        returnedSecrets: Object.keys(secretMap).length,
        returnedSecretKeys: Object.keys(secretMap)
      },
      "AzureKeyVaultSync: Secrets retrieval completed"
    );

    return secretMap;
  };

  return {
    syncSecrets,
    removeSecrets,
    getSecrets
  };
};
