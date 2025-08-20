export function web4_get() {
    const request = JSON.parse(env.input()).request;

      let response;
  
        if (request.path.includes(".html")) {
          response = {
      contentType: "text/html; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafybeiawpfimxcdjlci6yfgexcotjek67zk7e7l46vr67uvd6o44feffku" + request.path
          }
          } else if (request.path.includes(".mjs")) {
          response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafybeibfqrarmd7cbrdwt6zs44fib3g5rfgfpqfqz3w4ig5vrwtu6sutoq" + request.path // bafybeih4nfsst5v3vr2y2d2b7v2hpkh4jo7xqqbsd6kejezcr2dpjlqj5i" 
          }
          } else {
          response = {
      contentType: "text/html; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafybeiawpfimxcdjlci6yfgexcotjek67zk7e7l46vr67uvd6o44feffku/GameJsTest.html"
          }
          }
    env.value_return(JSON.stringify(response));
}

export function store_signing_key() {
  if (env.nft_supply_for_owner(env.signer_account_id()) > 0) {
    env.store_signing_key(env.block_timestamp_ms() + 24 * 60 * 60 * 1000);
  }
}


export function nft_metadata() {
  return {
    name: `CloseNodes`,
    symbol: `CLOSE`,
    icon: "https://ipfs.web4.near.page/ipfs/bafkreiabxfykl3eckbcgsgwi7wo3oedhes3gmdjtsu6yi4svqcgjmy6sd4",
    base_uri: null,
    reference: null,
    reference_hash: null,
  };
}


export function nft_mint() {
  const args = JSON.parse(env.input());

    const numberOfKeys = 200;
 let buskeys = [];
const numberOfShovels = 500;
  let shovels = [];
  const numberOfToothImplants = 60;
  let toothImplants = [];
  const numberOfScrewdrivers = 300;
  let screwdrivers = [];
  let numberOfCreeps = 4;
  let creeps = [];
  let numberOfSlingshots = 500;
  let slingshots = [];
  let numberOfCrowbars = 300;
  let crowbars = [];
  let numberOfPliers = 300;
  let pliers = [];
  let tuningForks = [];
  let remoteControls = [];
  let numberOfRemoteControls = 250;
  let numberOfChainCutters = 400;
  let chainCutters = [];

  if (args.token_id.includes("Buskey")) {
   for (let i = 0; i < numberOfKeys; i++) {
    buskeys.push(`Buskey${i}`);}
}
else if (args.token_id.includes("Rusty Shovel")) {
    for (let i = 0; i < numberOfShovels; i++) {
    shovels.push(`Rusty Shovel${i}`);}
} 
else if (args.token_id.includes("Tooth Implant")) {
    for (let i = 0; i < numberOfToothImplants; i++) {
    toothImplants.push(`Tooth Implant${i}`);}
}
else if (args.token_id.includes("Screwdriver")) {
    for (let i = 0; i < numberOfScrewdrivers; i++) {
    screwdrivers.push(`Screwdriver${i}`);}
}
else if (args.token_id.includes("Creep")) {
     for (let i = 0; i < numberOfCreeps; i++) {
    creeps.push(`Creep${i}`);}
} 
else if (args.token_id.includes("Slingshot")) {
  for (let i = 0; i < numberOfSlingshots; i++) {
    slingshots.push(`Slingshot${i}`);}
}
else if (args.token_id.includes("Crowbar")) {
    for (let i = 0; i < numberOfCrowbars; i++) {
    crowbars.push(`Crowbar${i}`); }
}
else if (args.token_id.includes("Pliers")) {
        for (let i = 0; i < numberOfPliers; i++) {
    pliers.push(`Pliers${i}`);  }
}
else if (args.token_id.includes("Tuning Forks")) {
  for (let i = 0; i < 300; i++) {
    tuningForks.push(`Tuning Fork${i}`)
  }
}
else if (args.token_id.includes("Remote Control")) {
  for (let i = 0; i < numberOfRemoteControls; i++) {
    remoteControls.push(`Remote Control${i}`)
  }
} 
else if (args.token_id.includes("Chain Cutter")) {
  for (let i = 0; i < numberOfChainCutters; i++) {
    chainCutters.push(`Chain Cutter${i}`)
  }
} 

  

        if (buskeys.includes(args.token_id))
  {
     return JSON.stringify({
    title: `Close Protocol NFT #${args.token_id}`,
    description: `A Close Protocol testnet NFT`,
    media: `https://ipfs.web4.near.page/ipfs/bafkreiabxfykl3eckbcgsgwi7wo3oedhes3gmdjtsu6yi4svqcgjmy6sd4`,
 //   media_hash: env.sha256_utf8_to_base64(svgstring)
  });} else if (screwdrivers.includes(args.token_id))
  {
     return JSON.stringify({
    title: `Close Protocol NFT #${args.token_id}`,
    description: `A Close Protocol testnet NFT`,
    media: `https://ipfs.web4.near.page/ipfs/bafkreibnarxl4oltu6tzotyxwz3o6gb3kghz2d6xmuo2dca27fjximgsue`,
//    media_hash: env.sha256_utf8_to_base64(svgstring)
  });} else if (toothImplants.includes(args.token_id))
  {
     return JSON.stringify({
    title: `Close Protocol NFT #${args.token_id}`,
    description: `A Close Protocol testnet NFT`,
    media: `https://ipfs.web4.near.page/ipfs/bafkreigfjahcxjqvj2sfcx6bgve4tqrgu4xu6y34m3rpczppjupjtd7aqi`,
  //  media_hash: env.sha256_utf8_to_base64(svgstring)
  });}
  else if (crowbars.includes(args.token_id))
  {
     return JSON.stringify({
    title: `Close Protocol NFT #${args.token_id}`,
    description: `A Close Protocol testnet NFT`,
    media: `https://ipfs.web4.testnet.page/ipfs/bafybeihhpzpnzdad553zr52fuinsake2y3e5tdhqkss2um67zgvktqsade/CloseSprites/ItemDatabase/Crowbar.png`,
  //  media_hash: env.sha256_utf8_to_base64(svgstring)
  });}
  else if (shovels.includes(args.token_id))
  {
     return JSON.stringify({
    title: `Close Protocol NFT #${args.token_id}`,
    description: `A Close Protocol testnet NFT`,
    media: `https://ipfs.web4.near.page/ipfs/bafkreicbfddmbs52rc2ujverpjjarz5zgxxorp65f3l53zhagpr6ooqsma?filename=OldShovel.png`,
  //  media_hash: env.sha256_utf8_to_base64(svgstring)
  });} else if (creeps.includes(args.token_id))
  {
     return JSON.stringify({
       copies: 5,
    title: `Close Protocol NFT #${args.token_id}`,
    description: `A Close Protocol testnet NFT`,
    media: `https://ipfs.web4.testnet.page/ipfs/bafybeihhpzpnzdad553zr52fuinsake2y3e5tdhqkss2um67zgvktqsade/CloseSprites/ItemDatabase/Creep.png`,
  //  media_hash: env.sha256_utf8_to_base64(svgstring)
  });} else if (pliers.includes(args.token_id))
  {
     return JSON.stringify({
    copies: 300,
    title: `Close Protocol NFT #${args.token_id}`,
    description: `A Close Protocol testnet NFT`,
    media: `https://ipfs.web4.near.page/ipfs/bafybeihk7pygg7os7hd3lgt4emxctdk3rsbsewwotubrzibmaskzbhmpai/CloseNodesCode/CloseSprites/Pliers.png`,
  //  media_hash: env.sha256_utf8_to_base64(svgstring)
  });}
  else if (tuningForks.includes(args.token_id))
  {
     return JSON.stringify({
    copies: 300,
    title: `Close Protocol NFT #${args.token_id}`,
    description: `A Close Protocol testnet NFT`,
    media: `https://ipfs.web4.near.page/ipfs/bafybeig5pus6cidno7lj7urximimyq6ceqqw7gpyvl6zrpft76v3ab6qhi/CloseNodesCode2/CloseSprites/TuningFork.png`,
  //  media_hash: env.sha256_utf8_to_base64(svgstring)
  });}
     else if (slingshots.includes(args.token_id))
 {
   return JSON.stringify({
    copies: 500,
    title: `Close Protocol NFT #${args.token_id}`,
    description: `A Close Protocol testnet NFT`,
    media: `https://ipfs.web4.testnet.page/ipfs/bafybeihhpzpnzdad553zr52fuinsake2y3e5tdhqkss2um67zgvktqsade/CloseSprites/ItemDatabase/Slingshot.png`,
  //  media_hash: env.sha256_utf8_to_base64(svgstring)
  });}
            else if (remoteControls.includes(args.token_id))
 {
     return JSON.stringify({
    copies: numberOfRemoteControls,
    title: `Close Protocol NFT #${args.token_id}`,
    description: `A Close Protocol testnet NFT`,
    media: `https://ipfs.web4.testnet.page/ipfs/bafybeihhpzpnzdad553zr52fuinsake2y3e5tdhqkss2um67zgvktqsade/CloseSprites/ItemDatabase/Remote.png`,
  //  media_hash: env.sha256_utf8_to_base64(svgstring)
  });}
            else if (chainCutters.includes(args.token_id))
 {
     return JSON.stringify({
    copies: numberOfChainCutters,
    title: `Close Protocol NFT #${args.token_id}`,
    description: `A Close Protocol testnet NFT`,
    media: `https://ipfs.web4.testnet.page/ipfs/bafybeihhpzpnzdad553zr52fuinsake2y3e5tdhqkss2um67zgvktqsade/CloseSprites/ItemDatabase/ChainCutter.png`,
  //  media_hash: env.sha256_utf8_to_base64(svgstring)
  });}

        else  { env.panic('not a valid token');

  }
}


/**
 * @returns 
*/

export function nft_payout() {
  const args = JSON.parse(env.input());
  const balance = BigInt(args.balance);
  const payout = {};
  const token_owner_id = JSON.parse(env.nft_token(args.token_id)).owner_id;
  const contract_owner = env.contract_owner();

  const addPayout = (account, amount) => {
    if (!payout[account]) {
      payout[account] = 0n;
    }
    payout[account] += amount;
  };
  addPayout(token_owner_id, balance * BigInt(80_00) / BigInt(100_00));
  addPayout(contract_owner, balance * BigInt(20_00) / BigInt(100_00));
  Object.keys(payout).forEach(k => payout[k] = payout[k].toString());
  return JSON.stringify({ payout });
}


                                                           


