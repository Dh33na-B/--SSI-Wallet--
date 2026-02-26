package SSI.Wallet.Identity.service;

import SSI.Wallet.Identity.dto.holder.AccessControlRequest;
import SSI.Wallet.Identity.dto.holder.CreateDocumentTypeRequest;
import SSI.Wallet.Identity.dto.holder.DocumentTypeResponse;
import SSI.Wallet.Identity.dto.holder.HolderDocumentResponse;
import SSI.Wallet.Identity.dto.holder.ShareProofRequest;
import SSI.Wallet.Identity.dto.holder.UploadDocumentRequest;
import SSI.Wallet.Identity.model.entity.CredentialEntity;
import SSI.Wallet.Identity.model.entity.DocumentKeyEntity;
import SSI.Wallet.Identity.model.entity.UserEntity;
import java.util.List;
import java.util.UUID;

public interface HolderService {

    UserEntity getHolderProfile(UUID holderId);

    List<CredentialEntity> getHolderCredentials(UUID holderId);

    List<HolderDocumentResponse> getHolderDocuments(UUID holderId);

    List<DocumentTypeResponse> getDocumentTypes();

    DocumentTypeResponse createDocumentType(CreateDocumentTypeRequest request);

    HolderDocumentResponse uploadEncryptedDocument(UploadDocumentRequest request);

    DocumentKeyEntity grantDocumentAccess(AccessControlRequest request);

    String shareSelectiveProof(ShareProofRequest request);
}
