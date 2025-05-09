from algopy import (
    ARC4Contract,
    Bytes,
    String,
    UInt64,
    Account,
    Txn,
    Global,
    GlobalState,
    LocalState,
)
from algopy import arc4


class BookContract(ARC4Contract):
    ##########################
    # Global state variables #
    ##########################
    # USER_ID = USER FIRST NAME | USER LAST INITIAL | USER YYYY | USER MM |
    #           USER BIRTH_CITY | USER BIRTH COUNTRY |
    #           MOTHERS FIRST NAME | MOTHERS LAST INITIAL | MOTHERS YYYY | MOTHERS MM |
    #           FATHERS FIRST NAME | FATHERS LAST INITIAL | FATHERS YYYY | FATHERS MM
    # g_user_id: Bytes

    # BOOK_ID = UNIQUE ID PER BOOK
    # g_book_id: Bytes

    # CONTRACT ADDRESS: ADDRESS THAT IS ALLOWED TO INTERACT WITH THE SMART CONTRACT
    # g_address: Account

    # STATUS: INACTIVE-INIT > ACTIVE > INACTIVE-STOP | INACTIVE-SOLD
    # g_status: String

    # PARAMETERS: REGION | ASSET CLASS | INSTRUMENT CLASS | ETC FOR EASY LOOKUP
    # g_params: Bytes

    #########################
    # Local state variables #
    #########################

    # ORDER FILE
    # l_book_hash: Bytes

    # RESEARCH FILE
    # l_research_hash: Bytes

    # PARAMETERS: PLACEHOLDER FOR FUTURE REFERENCE
    # l_params: Bytes

    def __init__(self) -> None:
        self.g_user_id = GlobalState(Bytes, key="user_id")
        self.g_book_id = GlobalState(Bytes, key="book_id")
        self.g_address = GlobalState(Account, key="address")
        self.g_status = GlobalState(String, key="status")
        self.g_params = GlobalState(Bytes, key="params")

        self.l_book_hash = LocalState(Bytes, key="book_hash")
        self.l_research_hash = LocalState(Bytes, key="research_hash")
        self.l_params = LocalState(Bytes, key="params")

    @arc4.abimethod()
    def initialize(self, user_id: Bytes, book_id: Bytes, parameters: Bytes) -> UInt64:
        """Initialize the contract with required parameters."""
        # Set global state
        self.g_user_id.value = user_id
        self.g_book_id.value = book_id
        self.g_address.value = Account(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
        )
        self.g_params.value = parameters
        self.g_status.value = String("INACTIVE-INIT")

        return UInt64(1)

    @arc4.abimethod(allow_actions=["OptIn"])
    def opt_in(self) -> UInt64:
        """Handle user opt-in to the contract."""
        # Validate that only the specified user can opt in
        assert Txn.sender == self.g_address.value, "Only authorized user can opt in"
        assert self.g_status.value == String("ACTIVE"), "Contract must be active"

        # Initialize local state
        self.l_book_hash[Txn.sender] = Bytes(b"NAN")
        self.l_research_hash[Txn.sender] = Bytes(b"NAN")
        self.l_params[Txn.sender] = Bytes(b"NAN")

        return UInt64(1)

    @arc4.abimethod(allow_actions=["CloseOut"])
    def close_out(self) -> UInt64:
        """Handle user closing out from the contract."""
        assert Txn.sender == self.g_address.value, "Only authorized user can close out"

        # Reset local state (though this is unnecessary as values will be deleted)
        self.l_book_hash[Txn.sender] = Bytes(b"NAN")
        self.l_research_hash[Txn.sender] = Bytes(b"NAN")
        self.l_params[Txn.sender] = Bytes(b"NAN")

        return UInt64(1)

    @arc4.abimethod()
    def update_global(
        self,
        new_user_id: Bytes,
        new_book_id: Bytes,
        new_address: Account,
        new_params: Bytes,
    ) -> UInt64:
        """Update the global parameters of the contract."""
        assert (
            Txn.sender == Global.creator_address
        ), "Only creator can supdate parameters"
        assert (
            (self.g_user_id.value != new_user_id)
            or (self.g_book_id.value != new_book_id)
            or (self.g_address.value != new_address)
            or (self.g_params.value != new_params)
        ), "New parameters must be different"

        # Update global parameters
        self.g_user_id.value = new_user_id
        self.g_book_id.value = new_book_id
        self.g_address.value = new_address
        self.g_params.value = new_params
        self.g_status.value = String("ACTIVE")

        return UInt64(1)

    @arc4.abimethod()
    def update_status(self, new_status: String) -> UInt64:
        """Update the status of the contract."""
        assert Txn.sender == Global.creator_address, "Only creator can update status"

        # Update global status
        self.g_status.value = new_status

        return UInt64(1)

    @arc4.abimethod()
    def update_local(
        self, book_hash: Bytes, research_hash: Bytes, params: Bytes
    ) -> UInt64:
        """Update the local state for the user."""
        assert (
            Txn.sender == self.g_address.value
        ), "Only authorized user can update local state"
        assert self.g_status.value == String("ACTIVE"), "Contract must be active"

        # Ensure at least one value is changing
        assert (
            self.l_book_hash[Txn.sender] != book_hash
            or self.l_research_hash[Txn.sender] != research_hash
            or self.l_params[Txn.sender] != params
        ), "At least one parameter must change"

        # Update local state
        self.l_book_hash[Txn.sender] = book_hash
        self.l_research_hash[Txn.sender] = research_hash
        self.l_params[Txn.sender] = params

        return UInt64(1)

    @arc4.abimethod(allow_actions=["DeleteApplication"])
    def delete_application(self) -> UInt64:
        """Delete the contract if it's inactive."""
        assert (
            Txn.sender == Global.creator_address
        ), "Only creator can delete application"
        assert self.g_status.value == String(
            "INACTIVE-STOP"
        ) or self.g_status.value == String(
            "INACTIVE-SOLD"
        ), "Contract must be inactive to delete"

        return UInt64(1)
