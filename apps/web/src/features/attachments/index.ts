// apps/web/src/features/attachments/index.ts
//
// Public surface of the attachments feature module (task 5.3).

export {
  uploadAttachment,
  AttachmentUploadError,
  type UploadAttachmentOptions,
} from './upload.js';

export {
  downloadAttachment,
  AttachmentDownloadError,
  type DownloadAttachmentOptions,
  type DownloadResult,
  type NotFoundError,
  type DecryptError,
} from './download.js';

export {
  LocalAttachmentsStore,
  DEFAULT_MAX_BYTES,
  type CachedAttachment,
  type LocalAttachmentsStoreOptions,
  type PutCiphertextArgs,
  type PutPlaintextArgs,
} from './cache.js';

export {
  AttachmentView,
  TAG_FAILURE_PLACEHOLDER,
  NOT_FOUND_PLACEHOLDER,
  type AttachmentViewProps,
} from './AttachmentView.js';
