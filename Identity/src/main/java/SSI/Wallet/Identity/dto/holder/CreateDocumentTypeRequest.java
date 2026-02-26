package SSI.Wallet.Identity.dto.holder;

import java.util.UUID;

public record CreateDocumentTypeRequest(
        UUID holderId,
        String name
) {
}
