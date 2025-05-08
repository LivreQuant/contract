from algopy import ARC4Contract, ByteArray, String, UInt64, Address
from algopy.arc4 import abimethod
from algopy.annotation import account, application_id, on_completion


class AssetsContract(ARC4Contract):
    # Global state variables
    global_user_id: ByteArray
    global_asset_id: ByteArray
    global_params: ByteArray
    global_status: String

    # Local state variables
    local_asset_hash: ByteArray
    local_research_hash: ByteArray
    local_params: ByteArray

    # Contract address that's allowed to interact with this contract
    user_address: Address

    def __init__(self, user_address: Address = None):
        self.user_address = user_address or Address("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")

    @abimethod()
    def initialize(self, user_id: ByteArray, asset_id: ByteArray, parameters: ByteArray) -> UInt64:
        """Initialize the contract with required parameters."""
        # Set global state
        self.global_user_id = user_id
        self.global_asset_id = asset_id
        self.global_params = parameters
        self.global_status = String("ACTIVE")

        return UInt64(1)

    @abimethod(on_complete=on_completion.OptIn)
    def opt_in(self) -> UInt64:
        """Handle user opt-in to the contract."""
        # Validate that only the specified user can opt in
        assert self.txn.sender == self.user_address, "Only authorized user can opt in"
        assert self.global_status == String("ACTIVE"), "Contract must be active"

        # Initialize local state
        self.local_asset_hash = ByteArray("NAN")
        self.local_research_hash = ByteArray("NAN")
        self.local_params = ByteArray("NAN")

        return UInt64(1)

    @abimethod(on_complete=on_completion.CloseOut)
    def close_out(self) -> UInt64:
        """Handle user closing out from the contract."""
        assert self.txn.sender == self.user_address, "Only authorized user can close out"
        assert self.global_status == String("ACTIVE"), "Contract must be active"

        # Reset local state (though this is unnecessary as values will be deleted)
        self.local_asset_hash = ByteArray("NAN")
        self.local_research_hash = ByteArray("NAN")
        self.local_params = ByteArray("NAN")

        return UInt64(1)

    @abimethod()
    def update_params(self, new_params: ByteArray) -> UInt64:
        """Update the global parameters of the contract."""
        assert self.txn.sender == self.app.creator, "Only creator can update parameters"
        assert self.global_params != new_params, "New parameters must be different"

        # Update global parameters
        self.global_params = new_params

        return UInt64(1)

    @abimethod()
    def update_status(self, new_status: String) -> UInt64:
        """Update the status of the contract."""
        assert self.txn.sender == self.app.creator, "Only creator can update status"
        assert new_status == String("ACTIVE") or new_status == String("INACTIVE"), "Status must be ACTIVE or INACTIVE"

        # Update global status
        self.global_status = new_status

        return UInt64(1)

    @abimethod()
    def update_local(self, file_hash: ByteArray, research_hash: ByteArray, params: ByteArray) -> UInt64:
        """Update the local state for the user."""
        assert self.txn.sender == self.user_address, "Only authorized user can update local state"
        assert self.global_status == String("ACTIVE"), "Contract must be active"

        # Ensure at least one value is changing
        assert (self.local_asset_hash != file_hash or
                self.local_research_hash != research_hash or
                self.local_params != params), "At least one parameter must change"

        # Update local state
        self.local_asset_hash = file_hash
        self.local_research_hash = research_hash
        self.local_params = params

        return UInt64(1)

    @abimethod(on_complete=on_completion.DeleteApplication)
    def delete_application(self) -> UInt64:
        """Delete the contract if it's inactive."""
        assert self.txn.sender == self.app.creator, "Only creator can delete application"
        assert self.global_status == String("INACTIVE"), "Contract must be inactive to delete"

        return UInt64(1)
