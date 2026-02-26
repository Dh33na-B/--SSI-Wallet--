package SSI.Wallet.Identity.dto.holder;

import java.time.LocalDateTime;
import java.util.UUID;

public record HolderDocumentResponse(
        UUID id,
        String fileName,
        String documentType,
        String ipfsCid,
        String status,
        LocalDateTime uploadedAt
) {
}
