// Find all our documentation at https://docs.near.org
import {
  view,
  call,
  initialize,
  near,
  NearBindgen,
  NearPromise,
  PromiseIndex,
} from "near-sdk-js";
import { sha256 } from 'near-sdk-js/lib/api';
import { TextEncoder } from "near-sdk-js";
import { AccountId } from "near-sdk-js/lib/types";

const TEN_TGAS = BigInt("10000000000000");
const TWENTY_TGAS = BigInt("20000000000000");
const THIRTY_TGAS = BigInt("30000000000000");
const SIXTY_TGAS = BigInt("60000000000000");
const SOME_DEPOSIT = BigInt("10000000000000000000000");
const MORE_DEPOSIT = BigInt("20000000000000000000000");
const NO_DEPOSIT = BigInt(0);
const NO_ARGS = JSON.stringify({});

@NearBindgen({})
class CrossContractCall {
  hello_account: AccountId = "testgasrseight.testnet";
  tokens_for_owner: string[] = [];
  original_minters: string[][] = [];
  minter: AccountId = "thisaccount.testnet";
  token_id_now: string = "";
  token_ids_minted: string[] = [];
  token_and_minter: string[] = [];
  tokens_before_mint: string[][] = [];
  tokens_after_mint: string[][] = [];
  token_id: string = "";
  score_count: number = 0;
  token_ids_now: string[] = [];
  token_ids: string[] = [];
  token_id_here_new: string = "";
  token_name: string = "";

  @view({})
  calculate_sha_256(inputText: string): string {
    const input = new TextEncoder().encode(inputText);
    const result = sha256(input);
    
    // Convert to Uint8Array
    const byteArray = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      byteArray[i] = result[i];
    }

    // Convert to hex string
    return Array.from(byteArray)
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');
  }

  @view({})
  get_account(): string {
    return this.hello_account;
  } 

  @call({})
  set_account({ hello_account }: { hello_account: AccountId }): void {
    near.log(`Saving account: ${hello_account}`);
    this.hello_account = hello_account;
  }

  @initialize({})
  init({ hello_account }: { hello_account: AccountId }) {
    this.hello_account = hello_account;
  }

  @call({})
  set_tokens_for_owner({}): void {
    this.tokens_for_owner = [];
  }

  @call({})
  set_token_ids_minted({}): void {
    this.token_ids_minted = [];
  }

  @view({})
  get_token_id(): string[] {
    return this.tokens_for_owner;
  }

  @view({})
  tokens_before_after(): boolean {
    return JSON.stringify(this.tokens_before_mint) === JSON.stringify(this.original_minters);
  }

  @view({})
  check_array(): string[] {
    return this.token_ids_minted;
  }

  @call({})
  push_token({token_id}: {token_id: string}): void {
    this.token_ids_minted.push(token_id);
  }

  @view({})
  get_original_minters(): string[][] {
    return this.original_minters;
  }

  @call({})
  set_original_minters({ original_minters }: { original_minters: string[][] }): void {
    this.original_minters = original_minters;
  }
  
  @call({payableFunction: true})
  mint_nft({ token_id }: { token_id: string }): NearPromise {
    let token_name_sha = token_id.replace(/\d+/g, '');
    near.log("token_name_sha = " + token_name_sha);
    let token_name_now = this.calculate_sha_256(token_name_sha);
    near.log(token_name_now);

    let token_name = "";
    let token_number_string = token_id.replace(/\D+/g, '');
    let token_number = parseInt(token_number_string, 10);

    near.log(token_id);
    near.log(token_number.toString());

    this.token_id = token_id;
    let token_copies: number = 0;
    let token_media: string = "";
    
    if (token_name_now === "226f915e0ecadc2eba5e6e5cf533ddcc0c4195e128f559cf3ad0985d515139fa") {
      token_copies = 500;
      token_media = "https://ipfs.web4.testnet.page/ipfs/bafybeihhpzpnzdad553zr52fuinsake2y3e5tdhqkss2um67zgvktqsade/CloseSprites/ItemDatabase/Slingshot.png";
      token_name = "Slingshot";
    } 
    else if (token_name_now === "1c5ab426970679fc5a6e7845e66534cac3d4a3b7219653c187e51b956454a789") {
      token_copies = 200;
      token_media = "https://ipfs.web4.testnet.page/ipfs/bafybeihhpzpnzdad553zr52fuinsake2y3e5tdhqkss2um67zgvktqsade/CloseSprites/ItemDatabase/Buskey.png";
      token_name = "Buskey";
    }
    else if (token_name_now === "3e21b6da330217c7376e210a109705487e1b1f7285cfb8e10a4a7ac2d82386b3") {
      token_copies = 300;
      token_media = "https://ipfs.web4.testnet.page/ipfs/bafybeihhpzpnzdad553zr52fuinsake2y3e5tdhqkss2um67zgvktqsade/CloseSprites/ItemDatabase/Screwdriver.png";
      token_name = "Screwdriver";
    }
    else if (token_name_now === "314ec57c307fde101d035f18c305ab861ef09c3ec27745570bda0b67809af839") {
      token_name = "Golden Key";
    }
    else if (token_name_now === "8f09dd9ff416a80b026c46f1f593e417fafb535664ae0d91a9ca49be097d71eb") {
      token_copies = 280;
      token_media = "https://ipfs.web4.testnet.page/ipfs/bafybeihhpzpnzdad553zr52fuinsake2y3e5tdhqkss2um67zgvktqsade/CloseSprites/ItemDatabase/Creep.png";
      token_name = "Creep";
    }
    else if (token_name_now === "4566f0ab93c81e972a0cc7b99c32ddb5193c4cfe867dbbb6f046e5e5cba847ac") {
      token_copies = 1000;
      token_media = "https://ipfs.web4.near.page/ipfs/bafkreicbfddmbs52rc2ujverpjjarz5zgxxorp65f3l53zhagpr6ooqsma?filename=OldShovel.png"; 
      token_name = "Rusty Shovel";
    }
    else if (token_name_now === "e3bb59df64cc812616f7f9c74886f0c2c4bdf787557ea9b6bb00e9261be7094e") {
      token_copies = 300;
      token_media = "https://ipfs.web4.testnet.page/ipfs/bafybeihhpzpnzdad553zr52fuinsake2y3e5tdhqkss2um67zgvktqsade/CloseSprites/ItemDatabase/Remote.png"; 
      token_name = "Remote Control";
    }
    else if (token_name_now === "bae103eef86e0965c0f07992e82ebf884049b8fdbfee522e6bfde88defb678e2") {
      token_copies = 400;
      token_media = "https://ipfs.web4.testnet.page/ipfs/bafybeihhpzpnzdad553zr52fuinsake2y3e5tdhqkss2um67zgvktqsade/CloseSprites/ItemDatabase/Crowbar.png";
      token_name = "Crowbar";
    }
    else if (token_name_now === "fdcbe1eecdc9a4ebe838f99308984f450326bf8b245ac24570fc3838234c02cd") {
      token_copies = 200;
      token_media = "https://ipfs.web4.near.page/ipfs/bafybeihk7pygg7os7hd3lgt4emxctdk3rsbsewwotubrzibmaskzbhmpai/CloseNodesCode/CloseSprites/Pliers.png";
      token_name = "Pliers";
    }
    else if (token_name_now === "7a8975104c399b304a90d1f968edc2fff49ec915ed257118974cd51de76909bf") {
      token_copies = 500;
      token_media = "https://ipfs.web4.near.page/ipfs/bafybeig5pus6cidno7lj7urximimyq6ceqqw7gpyvl6zrpft76v3ab6qhi/CloseNodesCode2/CloseSprites/RustyKey.png";
      token_name = "Old Key";
    }
    else if (token_name_now === "cc7c47b4523a6b4180bb0e9105bef427599f656c9edbd53024e4d7aa04aa8175") {
      token_copies = 250;
      token_media = "https://ipfs.web4.testnet.page/ipfs/bafybeihhpzpnzdad553zr52fuinsake2y3e5tdhqkss2um67zgvktqsade/CloseSprites/ItemDatabase/ChainCutter.png";
      token_name = "Chain Cutter";
    }
    else if (token_name_now === "12e22b099dd8bfa5f2334d2734cf245e4fe7a960b0882106537a3b5568dd16c9") {
      token_copies = 350;
      token_media = "https://ipfs.web4.near.page/ipfs/bafkreigfjahcxjqvj2sfcx6bgve4tqrgu4xu6y34m3rpczppjupjtd7aqi";
      token_name = "Tooth Implant";
    }
    else {
      near.log("Unknown token type");
      throw new Error("Unknown token type");
    }

    this.token_id_now = token_name + token_number_string;
    this.token_id = this.token_id_now;

    const predecessor = near.predecessorAccountId();
    const hasMinted = this.original_minters.some(
     innerArray => innerArray[0] === predecessor && innerArray[1] === token_name
    );

//Controlliing who can mint
if (!this.original_minters.some((innerArray => innerArray.includes(near.signerAccountId()) && innerArray.includes(token_name)))) {
 
   if (!hasMinted && token_number <= token_copies) {
      this.minter = predecessor;
     this.token_name = token_name;
      const mintArgs = JSON.stringify({
        token_id: this.token_id_now,
        token_owner_id: near.signerAccountId()
      });

      const promise = NearPromise.new(this.hello_account)
        .functionCall(
          "nft_mint",
          mintArgs,
          SOME_DEPOSIT,
          THIRTY_TGAS
        )
        .then(
          NearPromise.new(near.currentAccountId())
            .functionCall(
              "mint_nft_callback",
              NO_ARGS,
              NO_DEPOSIT,
              THIRTY_TGAS
            )
        );

      return promise.asReturn();
    }  else { near.log("Not allowed") 
    }} 
    else {
      near.log("Minting not allowed");
      throw new Error("Minting not allowed");
    }
  }

  @call({ privateFunction: true, payableFunction: true })
  mint_nft_callback(): boolean {
    let { success } = promiseResult();

    if (success) {
      near.log(`Success!`);
      this.original_minters.push([this.minter, this.token_name]);
      this.token_ids_minted.push(this.token_id);
      return true;
    } else {
      near.log("Promise failed...");
      return false;
    }
  } 
}

function promiseResult(): { result: string; success: boolean } {
  let result, success;

  try {
    result = near.promiseResult(0 as PromiseIndex);
    success = true;
  } catch {
    result = "";
    success = false;
  }

  return { result, success };
}
