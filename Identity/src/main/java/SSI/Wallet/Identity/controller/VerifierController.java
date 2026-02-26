package SSI.Wallet.Identity.controller;

import SSI.Wallet.Identity.dto.verifier.RequestProofRequest;
import SSI.Wallet.Identity.dto.verifier.ProofRequestSummaryResponse;
import SSI.Wallet.Identity.dto.verifier.VerifierCredentialOptionResponse;
import SSI.Wallet.Identity.dto.verifier.VerifierHolderOptionResponse;
import SSI.Wallet.Identity.dto.verifier.VerificationDecisionRequest;
import SSI.Wallet.Identity.dto.verifier.VerifyCredentialRequest;
import SSI.Wallet.Identity.model.entity.ProofLogEntity;
import SSI.Wallet.Identity.service.VerifierService;
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
@RequestMapping("/api/verifier")
@RequiredArgsConstructor
public class VerifierController {

    private final VerifierService verifierService;

    @PostMapping("/proof/request")
    public ResponseEntity<ProofRequestSummaryResponse> requestProof(@RequestBody RequestProofRequest request) {
        return ResponseEntity.ok(verifierService.requestProof(request));
    }

    @GetMapping("/{verifierId}/holders")
    public ResponseEntity<List<VerifierHolderOptionResponse>> getVerifierHolders(@PathVariable UUID verifierId) {
        return ResponseEntity.ok(verifierService.getVerifierHolders(verifierId));
    }

    @GetMapping("/{verifierId}/holders/{holderId}/credentials")
    public ResponseEntity<List<VerifierCredentialOptionResponse>> getVerifierCredentialOptions(
            @PathVariable UUID verifierId,
            @PathVariable UUID holderId
    ) {
        return ResponseEntity.ok(verifierService.getVerifierCredentialOptions(verifierId, holderId));
    }

    @GetMapping("/{verifierId}/requests")
    public ResponseEntity<List<ProofRequestSummaryResponse>> getVerifierRequests(@PathVariable UUID verifierId) {
        return ResponseEntity.ok(verifierService.getVerifierRequests(verifierId));
    }

    @GetMapping("/{verifierId}/history")
    public ResponseEntity<List<ProofLogEntity>> getVerifierHistory(@PathVariable UUID verifierId) {
        return ResponseEntity.ok(verifierService.getVerifierHistory(verifierId));
    }

    @PostMapping("/credentials/verify")
    public ResponseEntity<ProofLogEntity> verifyCredential(@RequestBody VerifyCredentialRequest request) {
        return ResponseEntity.ok(verifierService.verifyCredential(request));
    }

    @PostMapping("/credentials/decision")
    public ResponseEntity<ProofLogEntity> submitDecision(@RequestBody VerificationDecisionRequest request) {
        return ResponseEntity.ok(verifierService.submitDecision(request));
    }
}
