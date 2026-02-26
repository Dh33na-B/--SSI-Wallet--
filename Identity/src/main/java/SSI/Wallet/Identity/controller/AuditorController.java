package SSI.Wallet.Identity.controller;

import SSI.Wallet.Identity.model.entity.AuditLogEntity;
import SSI.Wallet.Identity.model.entity.ProofLogEntity;
import SSI.Wallet.Identity.model.entity.RevocationHistoryEntity;
import SSI.Wallet.Identity.service.AuditorService;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auditor")
@RequiredArgsConstructor
public class AuditorController {

    private final AuditorService auditorService;

    @GetMapping("/{auditorId}/logs/audit")
    public ResponseEntity<List<AuditLogEntity>> getAuditLogs(@PathVariable UUID auditorId) {
        return ResponseEntity.ok(auditorService.getAuditLogs(auditorId));
    }

    @GetMapping("/{auditorId}/logs/revocations")
    public ResponseEntity<List<RevocationHistoryEntity>> getRevocationHistory(@PathVariable UUID auditorId) {
        return ResponseEntity.ok(auditorService.getRevocationHistory(auditorId));
    }

    @GetMapping("/{auditorId}/logs/proofs")
    public ResponseEntity<List<ProofLogEntity>> getProofLogs(@PathVariable UUID auditorId) {
        return ResponseEntity.ok(auditorService.getProofLogs(auditorId));
    }
}
