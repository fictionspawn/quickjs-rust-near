export function web4_get() {
    const request = JSON.parse(env.input()).request;

      let response;
    //https://ipfs.web4.near.page/ipfs/bafybeicxmjoxqgzhr55gl34umnffemw3i5w7ja54g6vksswzrnlszua5xe/https://ipfs.web4.near.page/ipfs/bafybeicxmjoxqgzhr55gl34umnffemw3i5w7ja54g6vksswzrnlszua5xe/  
	//CloseGameOldNew.car - https://ipfs.web4.near.page/ipfs/bafybeicblwsfdi7jjrahpmop64ehj2edivftgx7cxva32rnnpfteza4sea + request.path
  const codeUrl = "https://ipfs.web4.near.page/ipfs/bafybeidrv64w6zd5c2z2st3kqlzynqjimdnvewpacdps5lpp4jykah4c5m"

//Manage folder

  if  (request.path == "StartGame.mjs") {
        response = {
            contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreie7vvrfyclyjawkuswrze5xzqezo5nejhea2vnonqxioo2kxbhsey"
  };
  }
  else if (request.path.includes("Fullscreen.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: codeUrl + request.path
    };
  } 
    else if (request.path.includes("ImageDatabase.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreibydhr4uhogiufggfixha3se3bu5npm6gyzhdi2di2pfqx2im5myy"
    };
  } else if (request.path.includes("ItemDatabaseScript.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreihjrkkntcy5mn3bekjxfts6iim57wuuiragtrhh5o5q22doznplqy"
    };
  }  else if (request.path.includes("SceneItemClass.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreih4dy37yrje5waf2gbrhxy34q6ypw7qnwx6ytqdmg2pgs6dmiz2gq"
    };
  }  else if (request.path.includes("PlaceClass.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreihw2q5ux4swvxjj2wluxnunqejc6ntc7jnabqplivyxkbfcwrssoe"
    };
  }   else if (request.path.includes("SoundManager.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreib6fvbpr4fsledd4tdnqao7vf4ewyzjziwfvojpy65lffatm3bf3e"
    };
  } else if (request.path.includes("ButtonManager.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreih65p5w2e7h7urvsemsai7gtsdbedpecu4xlurtqbxm7qzp4nw6am"
    };
  }  else if (request.path.includes("RecoverInventory.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreiemaa6ae24fwc4jiy536f7q722aukepa2qoindj226liytsfs6j44"
    };
  }  else if (request.path.includes("InventoryScript.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreignepnusetulbatlbvwknanljmv75ycyi7y5saov54udt5t7e5z54"
    };
  }   else if (request.path.includes("AddNftItem.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreigqhyrpbulput2dqnbruy2zgxqsux4jkjvlgrcvisnl62cx3pgwc4"
    };
  } 

//Near folder

	else if (request.path.includes("MintNft.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreic5krbus5idulwvf2osr7stsziaaxqg7lwgksexr3nomxuizzumqa"
    };
  } else if (request.path.includes("NearConnection.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreiclde5dkajt7iho73r26xm73efjza7rdpomope5h2gn5tl55xwsvu"
    };
  } 

	//Animation folder

	else if (request.path.includes("BlueCreature.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreibfqzhg32fsydouookyc3vmfxfhd3xwavnewhu57t4opcgsywspn4"
    };
  } else if (request.path.includes("BusRoofMonster.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreihv4ftgwvmnp5qtu2hcgal5bxmvyipxenauqnsdaacvm4ibaknh4i"
    };
  } else if (request.path.includes("CaveMonsterAnimation.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreicyvnuiounq24d2p67od5isnl7fhijg4x7mrt3refbtulh26dlqxa"
    };
  } else if (request.path.includes("FallingLeafScript.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreibe2jfv2hgc6orqt6pzjn2hkumikxosrbrpn342i2mte7cfwaiqfe"
    };
  } else if (request.path.includes("MonsterSwarm.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreigl2py6onppy3qo5teylois3qlg6qv52wckesscuyuheem2jbnx5y"
    };
  } else if (request.path.includes("MrCringyProject.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreiahtch7udq5zyexk2g7fwesw4f5b5oowyw2aedoc6uftx7gzk4caa"
    };
  } else if (request.path.includes("OpenBunkerAnimation.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreieyclvxjhj2jm2fwpfsvbugqqavgwjzeijwcaovft2c2f7yjas63e"
    };
  } else if (request.path.includes("RiverBoatBowMonster.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreifscbzowf4ljf7lsf7fkjgfqcho4lb7viqzwkhy6vxzj7jo343sum"
    };
  } else if (request.path.includes("AlienMachinePuzzle.mjs")) {
      response = {
        contentType: "text/javascript; charset=UTF-8",
        bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreiegolhphtfvrb5chig35o6nd4ckllz5jnm4crzzl7owehvqsoxmeq"
      };
  }
    else if (request.path.includes("CreateAvatar.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreia2d3l674jxqdtxr6fjztqhtqezhdi5yt43774tzsx42z3lf5akqa"
    };
  }

	//Places folder bafkreiaktvkhaopfazuvxp25h2vgo2yr7ttgjjcqtld2u4j2ri7navs6ra

	else if (request.path.includes("BusSeatsScript.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreifm72crlg2mtpyg55jxiyjhis2lws57rrlqn6mp2hmaxyd5jszmyy"
    };
  } else if (request.path.includes("Bunker.mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreihwmc2nk6mt4o2t4wmrk6juzsmzpsdbrfzhd2a75or5z4x4d3eeve"
    };
  } else if (request.path.includes(".mjs")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: codeUrl + request.path
    };
  }
  else if (request.path.includes(".png")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: codeUrl + request.path
    };
  }  /* else if (request.path.includes("BlueBall.png")) {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafkreicuuderqbpjxw3qmmpfqw5qn4coqzswiedoc74qingwzjrajj4zee"// + request.path
    };
  }*/ else if (request.path.includes(".jpg")) {
    response = {
      contentType: "image/jpeg",
      bodyUrl: codeUrl + request.path
    };
  } else if (request.path.includes(".wav")) {
      response = {
      contentType: "audio/wav",
      bodyUrl: codeUrl + request.path 
    };
  } else if (request.path.includes(".mp3")) {
      response = {
      contentType: "audio/mpeg",
      bodyUrl: codeUrl + request.path 
    };
  } 
 else if (request.path.includes(".html")) {
     response = {
            contentType: "text/html; charset=UTF-8",
            bodyUrl: "https://ipfs.web4.near.page/ipfs/bafybeicxmjoxqgzhr55gl34umnffemw3i5w7ja54g6vksswzrnlszua5xe" + "/GameJsTest.html"
        };
  } else if (request.path.includes(".mjs")) {
    response = {
        contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafybeicxmjoxqgzhr55gl34umnffemw3i5w7ja54g6vksswzrnlszua5xe" + request.path
    };
  } else {
    response = {
      contentType: "text/html; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafybeicxmjoxqgzhr55gl34umnffemw3i5w7ja54g6vksswzrnlszua5xe"
    };
  }
    env.value_return(JSON.stringify(response));
}
/*
export function web4_get() {
  const request = JSON.parse(env.input()).request;

  let response;
	//let game_url = "https://ipfs.web4.near.page/ipfs/bafybeiee5k4t4r7udi5zlnxxauxiprc7n3loa5h74kuix572jo6foxquqa/";
  /*if (request.path.includes("Fullscreen") {
    response = {
      contentType: "text/javascript; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafybeiee5k4t4r7udi5zlnxxauxiprc7n3loa5h74kuix572jo6foxquqa/" + "Manage/Fullscreen.mjs",
    } ;
  } else if (request.path.includes("StartGame")) {
    response = {
      contentType: "text/javascript; charset= UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafybeiee5k4t4r7udi5zlnxxauxiprc7n3loa5h74kuix572jo6foxquqa/" + "Manage/StartGame.mjs"
    };
  }
  else
  if (request.path.includes("GameJsTest.html")) {    
    response = {
      contentType: "text/html; charset=UTF-8",
      bodyUrl: "https://ipfs.web4.near.page/ipfs/bafybeiee5k4t4r7udi5zlnxxauxiprc7n3loa5h74kuix572jo6foxquqa/GameJsTest.html" 
    };
  }
  env.value_return(JSON.stringify(response));
}
*/
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

  //let this_inlogged_accout = current_account_id();

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
/*
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

*/
                                                           


