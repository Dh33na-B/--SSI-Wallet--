package SSI.Wallet.Identity.service;

import SSI.Wallet.Identity.dto.verifier.RequestProofRequest;
import SSI.Wallet.Identity.dto.verifier.ProofRequestSummaryResponse;
import SSI.Wallet.Identity.dto.verifier.VerifierCredentialOptionResponse;
import SSI.Wallet.Identity.dto.verifier.VerifierHolderOptionResponse;
import SSI.Wallet.Identity.dto.verifier.VerificationDecisionRequest;
import SSI.Wallet.Identity.dto.verifier.VerifyCredentialRequest;
import SSI.Wallet.Identity.dto.holder.ShareProofRequest;
import SSI.Wallet.Identity.model.entity.ProofLogEntity;
import java.util.List;
import java.util.UUID;

public interface VerifierService {

    ProofRequestSummaryResponse requestProof(RequestProofRequest request);

    List<ProofRequestSummaryResponse> getVerifierRequests(UUID verifierId);

    List<ProofRequestSummaryResponse> getHolderRequests(UUID holderId);

    List<ProofLogEntity> getVerifierHistory(UUID verifierId);

    List<VerifierHolderOptionResponse> getVerifierHolders(UUID verifierId);

    List<VerifierCredentialOptionResponse> getVerifierCredentialOptions(UUID verifierId, UUID holderId);

    ProofRequestSummaryResponse processHolderProof(ShareProofRequest request);

    ProofLogEntity verifyCredential(VerifyCredentialRequest request);

    ProofLogEntity submitDecision(VerificationDecisionRequest request);
}
