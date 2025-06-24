use near_sdk::{ext_contract, AccountId};
use near_contract_standards::non_fungible_token::{TokenId};

// Validator interface, for cross-contract calls
#[ext_contract(hello_near)]
trait HelloNear {
    fn get_greeting(&self) -> String;
    fn set_greeting(&self, greeting: String);
    fn nft_mint(&self, token_id: TokenId, account_id: AccountId);
}
