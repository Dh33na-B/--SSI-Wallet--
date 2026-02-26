package SSI.Wallet.Identity.service;

import SSI.Wallet.Identity.dto.holder.AccessControlRequest;
import SSI.Wallet.Identity.dto.holder.ShareProofRequest;
import SSI.Wallet.Identity.model.entity.CredentialEntity;
import SSI.Wallet.Identity.model.entity.DocumentKeyEntity;
import SSI.Wallet.Identity.model.entity.UserEntity;
import java.util.List;
import java.util.UUID;

public interface HolderService {

    UserEntity getHolderProfile(UUID holderId);

    List<CredentialEntity> getHolderCredentials(UUID holderId);

    DocumentKeyEntity grantDocumentAccess(AccessControlRequest request);

    String shareSelectiveProof(ShareProofRequest request);
}
