package SSI.Wallet.Identity.service;

import SSI.Wallet.Identity.dto.issuer.AnchorCredentialRequest;
import SSI.Wallet.Identity.dto.issuer.IssueCredentialRequest;
import SSI.Wallet.Identity.dto.issuer.RevokeCredentialRequest;
import SSI.Wallet.Identity.dto.issuer.VerifyDocumentRequest;
import SSI.Wallet.Identity.model.entity.CredentialEntity;
import SSI.Wallet.Identity.model.entity.DocumentEntity;
import SSI.Wallet.Identity.model.entity.RevocationHistoryEntity;

public interface IssuerService {

    DocumentEntity verifyDocument(VerifyDocumentRequest request);

    CredentialEntity issueCredential(IssueCredentialRequest request);

    CredentialEntity anchorCredentialHash(AnchorCredentialRequest request);

    RevocationHistoryEntity revokeCredential(RevokeCredentialRequest request);
}
