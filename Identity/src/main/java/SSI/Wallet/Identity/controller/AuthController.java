package SSI.Wallet.Identity.controller;

import SSI.Wallet.Identity.dto.auth.MetaMaskLoginRequest;
import SSI.Wallet.Identity.dto.auth.MetaMaskLoginResponse;
import SSI.Wallet.Identity.dto.auth.MetaMaskRemoveAccountRequest;
import SSI.Wallet.Identity.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/metamask/login")
    public ResponseEntity<MetaMaskLoginResponse> loginWithMetaMask(
            @RequestBody MetaMaskLoginRequest request
    ) {
        return ResponseEntity.ok(authService.loginWithMetaMask(request));
    }

    @PostMapping("/metamask/remove-account")
    public ResponseEntity<Void> removeMetaMaskAccount(
            @RequestBody MetaMaskRemoveAccountRequest request
    ) {
        authService.removeMetaMaskAccount(request);
        return ResponseEntity.noContent().build();
    }
}
