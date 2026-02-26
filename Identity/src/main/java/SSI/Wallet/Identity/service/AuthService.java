package SSI.Wallet.Identity.service;

import SSI.Wallet.Identity.dto.auth.MetaMaskLoginRequest;
import SSI.Wallet.Identity.dto.auth.MetaMaskLoginResponse;
import SSI.Wallet.Identity.dto.auth.MetaMaskRemoveAccountRequest;

public interface AuthService {

    MetaMaskLoginResponse loginWithMetaMask(MetaMaskLoginRequest request);

    void removeMetaMaskAccount(MetaMaskRemoveAccountRequest request);
}
