from algopy import ARC4Contract, ByteArray, String, UInt64, Address
from algopy.arc4 import abimethod
from algopy.annotation import account, application_id, on_completion


class BookContract(ARC4Contract):
    ##########################
    # Global state variables #
    ##########################
    # USER_ID = LASTNAME | YYYYMMDD | MOTHERS MAIDEN NAME | FATHERS FIRST NAME | BIRTH_CITY
    g_user_id: ByteArray

    # BOOK_ID = UNIQUE ID PER BOOK
    g_book_id: ByteArray

    # CONTRACT ADDRESS: ADDRESS THAT IS ALLOWED TO INTERACT WITH THE SMART CONTRACT
    g_address: Address

    # STATUS: ACTIVE | INACTIVE-STOP | INACTIVE-SOLD
    g_status: String

    # PARAMETERS: REGION | ASSET CLASS | INSTRUMENT CLASS | ETC FOR EASY LOOKUP
    g_params: ByteArray

    #########################
    # Local state variables #
    #########################

    # ORDER FILE
    l_book_hash: ByteArray

    # RESEARCH FILE
    l_research_hash: ByteArray

    # PARAMETERS: PLACEHOLDER FOR FUTURE REFERENCE
    l_params: ByteArray

    def __init__(self, g_address: Address = None):
        self.g_address = g_address or Address("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")

    @abimethod()
    def initialize(self, user_id: ByteArray, book_id: ByteArray, parameters: ByteArray) -> UInt64:
        """Initialize the contract with required parameters."""
        # Set global state
        self.g_user_id = user_id
        self.g_book_id = book_id
        # self.g_address = address
        self.g_params = parameters
        self.g_status = String("ACTIVE")

        return UInt64(1)

    @abimethod(on_complete=on_completion.OptIn)
    def opt_in(self) -> UInt64:
        """Handle user opt-in to the contract."""
        # Validate that only the specified user can opt in
        assert self.txn.sender == self.g_address, "Only authorized user can opt in"
        assert self.g_status == String("ACTIVE"), "Contract must be active"

        # Initialize local state
        self.l_book_hash = ByteArray("NAN")
        self.l_research_hash = ByteArray("NAN")
        self.l_params = ByteArray("NAN")

        return UInt64(1)

    @abimethod(on_complete=on_completion.CloseOut)
    def close_out(self) -> UInt64:
        """Handle user closing out from the contract."""
        assert self.txn.sender == self.g_address, "Only authorized user can close out"
        assert self.g_status == String("ACTIVE"), "Contract must be active"

        # Reset local state (though this is unnecessary as values will be deleted)
        self.l_book_hash = ByteArray("NAN")
        self.l_research_hash = ByteArray("NAN")
        self.l_params = ByteArray("NAN")

        return UInt64(1)

    @abimethod()
    def update_address(self, new_address: ByteArray) -> UInt64:
        """Update the global parameters of the contract."""
        assert self.txn.sender == self.app.creator, "Only creator can update parameters"
        assert self.g_address != new_address, "New parameters must be different"

        # Update global parameters
        self.g_address = new_address

        return UInt64(1)

    @abimethod()
    def update_params(self, new_params: ByteArray) -> UInt64:
        """Update the global parameters of the contract."""
        assert self.txn.sender == self.app.creator, "Only creator can update parameters"
        assert self.g_params != new_params, "New parameters must be different"

        # Update global parameters
        self.g_params = new_params

        return UInt64(1)

    @abimethod()
    def update_status(self, new_status: String) -> UInt64:
        """Update the status of the contract."""
        assert self.txn.sender == self.app.creator, "Only creator can update status"
        assert (new_status == String("ACTIVE") or
                new_status == String("INACTIVE-STOP") or
                new_status == String("INACTIVE-SOLD")), "Status must be ACTIVE or INACTIVE-STOP or INACTIVE-SOLD"

        # Update global status
        self.g_status = new_status

        return UInt64(1)

    @abimethod()
    def update_local(self, book_hash: ByteArray, research_hash: ByteArray, params: ByteArray) -> UInt64:
        """Update the local state for the user."""
        assert self.txn.sender == self.g_address, "Only authorized user can update local state"
        assert self.g_status == String("ACTIVE"), "Contract must be active"

        # Ensure at least one value is changing
        assert (self.l_book_hash != book_hash or
                self.l_research_hash != research_hash or
                self.l_params != params), "At least one parameter must change"

        # Update local state
        self.l_book_hash = book_hash
        self.l_research_hash = research_hash
        self.l_params = params

        return UInt64(1)

    @abimethod(on_complete=on_completion.DeleteApplication)
    def delete_application(self) -> UInt64:
        """Delete the contract if it's inactive."""
        assert self.txn.sender == self.app.creator, "Only creator can delete application"
        assert (self.g_status == String("INACTIVE-STOP") or
                self.g_status == String("INACTIVE-SELL")), "Contract must be inactive to delete"

        return UInt64(1)
