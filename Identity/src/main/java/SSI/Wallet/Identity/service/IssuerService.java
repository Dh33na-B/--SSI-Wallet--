package SSI.Wallet.Identity.service;

import SSI.Wallet.Identity.dto.issuer.AnchorCredentialRequest;
import SSI.Wallet.Identity.dto.issuer.IssuerDocumentAccessResponse;
import SSI.Wallet.Identity.dto.issuer.IssuerDocumentDecisionRequest;
import SSI.Wallet.Identity.dto.issuer.IssuerDocumentQueueItemResponse;
import SSI.Wallet.Identity.dto.issuer.IssuerReviewRequestResponse;
import SSI.Wallet.Identity.dto.issuer.IssueCredentialRequest;
import SSI.Wallet.Identity.dto.issuer.RequestDocumentOpenRequest;
import SSI.Wallet.Identity.dto.issuer.RevokeCredentialRequest;
import SSI.Wallet.Identity.dto.issuer.VerifyDocumentRequest;
import SSI.Wallet.Identity.model.entity.CredentialEntity;
import SSI.Wallet.Identity.model.entity.DocumentEntity;
import SSI.Wallet.Identity.model.entity.RevocationHistoryEntity;
import java.util.List;
import java.util.UUID;

public interface IssuerService {

    List<IssuerDocumentQueueItemResponse> getSubmittedDocuments(UUID issuerId);

    IssuerReviewRequestResponse requestDocumentOpen(RequestDocumentOpenRequest request);

    IssuerDocumentAccessResponse getDocumentAccess(UUID issuerId, UUID documentId);

    IssuerDocumentQueueItemResponse decideDocument(IssuerDocumentDecisionRequest request);

    DocumentEntity verifyDocument(VerifyDocumentRequest request);

    CredentialEntity getDocumentCredential(UUID issuerId, UUID documentId);

    List<CredentialEntity> getIssuedCredentials(UUID issuerId);

    CredentialEntity issueCredential(IssueCredentialRequest request);

    CredentialEntity anchorCredentialHash(AnchorCredentialRequest request);

    RevocationHistoryEntity revokeCredential(RevokeCredentialRequest request);
}
