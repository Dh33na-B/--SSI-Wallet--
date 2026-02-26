package SSI.Wallet.Identity.controller;

import SSI.Wallet.Identity.dto.verifier.RequestProofRequest;
import SSI.Wallet.Identity.dto.verifier.VerificationDecisionRequest;
import SSI.Wallet.Identity.dto.verifier.VerifyCredentialRequest;
import SSI.Wallet.Identity.model.entity.ProofLogEntity;
import SSI.Wallet.Identity.service.VerifierService;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
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
    public ResponseEntity<Map<String, String>> requestProof(@RequestBody RequestProofRequest request) {
        String result = verifierService.requestProof(request);
        return ResponseEntity.ok(Map.of("message", result));
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
