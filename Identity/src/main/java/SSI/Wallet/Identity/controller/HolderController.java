package SSI.Wallet.Identity.controller;

import SSI.Wallet.Identity.dto.holder.AccessControlRequest;
import SSI.Wallet.Identity.dto.holder.CreateDocumentTypeRequest;
import SSI.Wallet.Identity.dto.holder.DocumentTypeResponse;
import SSI.Wallet.Identity.dto.holder.HolderDocumentResponse;
import SSI.Wallet.Identity.dto.holder.ShareProofRequest;
import SSI.Wallet.Identity.dto.holder.UploadDocumentRequest;
import SSI.Wallet.Identity.model.entity.CredentialEntity;
import SSI.Wallet.Identity.model.entity.DocumentKeyEntity;
import SSI.Wallet.Identity.model.entity.UserEntity;
import SSI.Wallet.Identity.service.HolderService;
import java.util.List;
import java.util.Map;
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
@RequestMapping("/api/holder")
@RequiredArgsConstructor
public class HolderController {

    private final HolderService holderService;

    @GetMapping("/{holderId}/profile")
    public ResponseEntity<UserEntity> getProfile(@PathVariable UUID holderId) {
        return ResponseEntity.ok(holderService.getHolderProfile(holderId));
    }

    @GetMapping("/{holderId}/credentials")
    public ResponseEntity<List<CredentialEntity>> getCredentials(@PathVariable UUID holderId) {
        return ResponseEntity.ok(holderService.getHolderCredentials(holderId));
    }

    @GetMapping("/{holderId}/documents")
    public ResponseEntity<List<HolderDocumentResponse>> getDocuments(@PathVariable UUID holderId) {
        return ResponseEntity.ok(holderService.getHolderDocuments(holderId));
    }

    @GetMapping("/document-types")
    public ResponseEntity<List<DocumentTypeResponse>> getDocumentTypes() {
        return ResponseEntity.ok(holderService.getDocumentTypes());
    }

    @PostMapping("/document-types")
    public ResponseEntity<DocumentTypeResponse> createDocumentType(
            @RequestBody CreateDocumentTypeRequest request
    ) {
        return ResponseEntity.ok(holderService.createDocumentType(request));
    }

    @PostMapping("/documents/upload")
    public ResponseEntity<HolderDocumentResponse> uploadDocument(
            @RequestBody UploadDocumentRequest request
    ) {
        return ResponseEntity.ok(holderService.uploadEncryptedDocument(request));
    }

    @PostMapping("/access")
    public ResponseEntity<DocumentKeyEntity> grantAccess(@RequestBody AccessControlRequest request) {
        return ResponseEntity.ok(holderService.grantDocumentAccess(request));
    }

    @PostMapping("/proof/share")
    public ResponseEntity<Map<String, String>> shareProof(@RequestBody ShareProofRequest request) {
        String result = holderService.shareSelectiveProof(request);
        return ResponseEntity.ok(Map.of("message", result));
    }
}
