package SSI.Wallet.Identity.controller;

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
import SSI.Wallet.Identity.service.IssuerService;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/issuer")
@RequiredArgsConstructor
public class IssuerController {

    private final IssuerService issuerService;

    @GetMapping("/{issuerId}/documents")
    public ResponseEntity<List<IssuerDocumentQueueItemResponse>> getDocuments(@PathVariable UUID issuerId) {
        return ResponseEntity.ok(issuerService.getSubmittedDocuments(issuerId));
    }

    @PostMapping("/documents/open")
    public ResponseEntity<IssuerReviewRequestResponse> requestDocumentOpen(
            @RequestBody RequestDocumentOpenRequest request
    ) {
        return ResponseEntity.ok(issuerService.requestDocumentOpen(request));
    }

    @GetMapping("/{issuerId}/documents/{documentId}/access")
    public ResponseEntity<IssuerDocumentAccessResponse> getDocumentAccess(
            @PathVariable UUID issuerId,
            @PathVariable UUID documentId
    ) {
        return ResponseEntity.ok(issuerService.getDocumentAccess(issuerId, documentId));
    }

    @PostMapping("/documents/decide")
    public ResponseEntity<IssuerDocumentQueueItemResponse> decideDocument(
            @RequestBody IssuerDocumentDecisionRequest request
    ) {
        return ResponseEntity.ok(issuerService.decideDocument(request));
    }

    @PostMapping("/documents/verify")
    public ResponseEntity<DocumentEntity> verifyDocument(@RequestBody VerifyDocumentRequest request) {
        return ResponseEntity.ok(issuerService.verifyDocument(request));
    }

    @GetMapping("/{issuerId}/documents/{documentId}/credential")
    public ResponseEntity<CredentialEntity> getDocumentCredential(
            @PathVariable UUID issuerId,
            @PathVariable UUID documentId
    ) {
        return ResponseEntity.ok(issuerService.getDocumentCredential(issuerId, documentId));
    }

    @GetMapping("/{issuerId}/credentials")
    public ResponseEntity<List<CredentialEntity>> getIssuedCredentials(@PathVariable UUID issuerId) {
        return ResponseEntity.ok(issuerService.getIssuedCredentials(issuerId));
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
