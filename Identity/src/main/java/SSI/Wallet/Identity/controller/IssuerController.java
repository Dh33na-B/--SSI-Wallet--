package SSI.Wallet.Identity.controller;

import SSI.Wallet.Identity.dto.issuer.AnchorCredentialRequest;
import SSI.Wallet.Identity.dto.issuer.IssueCredentialRequest;
import SSI.Wallet.Identity.dto.issuer.RevokeCredentialRequest;
import SSI.Wallet.Identity.dto.issuer.VerifyDocumentRequest;
import SSI.Wallet.Identity.model.entity.CredentialEntity;
import SSI.Wallet.Identity.model.entity.DocumentEntity;
import SSI.Wallet.Identity.model.entity.RevocationHistoryEntity;
import SSI.Wallet.Identity.service.IssuerService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/issuer")
@RequiredArgsConstructor
public class IssuerController {

    private final IssuerService issuerService;

    @PostMapping("/documents/verify")
    public ResponseEntity<DocumentEntity> verifyDocument(@RequestBody VerifyDocumentRequest request) {
        return ResponseEntity.ok(issuerService.verifyDocument(request));
    }

    @PostMapping("/credentials")
    public ResponseEntity<CredentialEntity> issueCredential(@RequestBody IssueCredentialRequest request) {
        return ResponseEntity.ok(issuerService.issueCredential(request));
    }

    @PostMapping("/credentials/anchor")
    public ResponseEntity<CredentialEntity> anchorCredentialHash(@RequestBody AnchorCredentialRequest request) {
        return ResponseEntity.ok(issuerService.anchorCredentialHash(request));
    }

    @PostMapping("/credentials/revoke")
    public ResponseEntity<RevocationHistoryEntity> revokeCredential(@RequestBody RevokeCredentialRequest request) {
        return ResponseEntity.ok(issuerService.revokeCredential(request));
    }
}
