package SSI.Wallet.Identity.service;

import SSI.Wallet.Identity.dto.holder.AccessControlRequest;
import SSI.Wallet.Identity.dto.holder.CreateDocumentTypeRequest;
import SSI.Wallet.Identity.dto.holder.DocumentTypeResponse;
import SSI.Wallet.Identity.dto.holder.HolderCredentialAccessResponse;
import SSI.Wallet.Identity.dto.holder.HolderDocumentResponse;
import SSI.Wallet.Identity.dto.holder.IssuerEncryptionKeyResponse;
import SSI.Wallet.Identity.dto.holder.HolderReviewRequestResponse;
import SSI.Wallet.Identity.dto.holder.RespondReviewRequest;
import SSI.Wallet.Identity.dto.holder.ShareProofRequest;
import SSI.Wallet.Identity.dto.holder.UploadDocumentRequest;
import SSI.Wallet.Identity.dto.verifier.ProofRequestSummaryResponse;
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

    List<IssuerEncryptionKeyResponse> getAvailableIssuers();

    DocumentTypeResponse createDocumentType(CreateDocumentTypeRequest request);

    HolderDocumentResponse uploadEncryptedDocument(UploadDocumentRequest request);

    List<HolderReviewRequestResponse> getHolderReviewRequests(UUID holderId);

    HolderReviewRequestResponse respondReviewRequest(RespondReviewRequest request);

    DocumentKeyEntity grantDocumentAccess(AccessControlRequest request);

    List<ProofRequestSummaryResponse> getProofRequests(UUID holderId);

    HolderCredentialAccessResponse getCredentialAccess(UUID holderId, String credentialId);

    ProofRequestSummaryResponse shareSelectiveProof(ShareProofRequest request);
}
