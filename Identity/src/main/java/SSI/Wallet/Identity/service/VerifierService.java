package SSI.Wallet.Identity.service;

import SSI.Wallet.Identity.dto.verifier.RequestProofRequest;
import SSI.Wallet.Identity.dto.verifier.VerificationDecisionRequest;
import SSI.Wallet.Identity.dto.verifier.VerifyCredentialRequest;
import SSI.Wallet.Identity.model.entity.ProofLogEntity;

public interface VerifierService {

    String requestProof(RequestProofRequest request);

    ProofLogEntity verifyCredential(VerifyCredentialRequest request);

    ProofLogEntity submitDecision(VerificationDecisionRequest request);
}
