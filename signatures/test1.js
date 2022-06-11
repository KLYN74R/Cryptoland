//https://github.com/ameba23/dkg/blob/master/example.js
//Для отправки приватных данных можно использовать ассиметричное постквантовое шифрование NTRU encrypt или например симметричный AES-256 в каком-то из безопасных режимов
//

import * as dkg from './tbls_index.js'
import blsA from 'bls-wasm'



await blsA.init()

let generateTBLS=(threshold,myPubId,pubKeysArr)=>{

    let signers=pubKeysArr.map(id => {

        const sk = new blsA.SecretKey()
      
        sk.setHashOf(Buffer.from([id]))
      
        return {id:sk,recievedShares:[],arrId:id}
    
    })

    //Вот процесс генерации для участников - они могут это делать приватно у себя
    //Generation process - signers can do it privately on theirs machines
    const {verificationVector,secretKeyContribution} = dkg.generateContribution(blsA,signers.map(x=>x.id),threshold)
    
    //To transfer over network in hex
    //Verification vector можем публиковать - для каждого в группе. Только запоминать порядок индексов
    let serializedVerificationVector=verificationVector.map(x=>x.serializeToHexStr())
    let serializedSecretKeyContribution=secretKeyContribution.map(x=>x.serializeToHexStr())

    //console.log('Verification Vector SERIALIZE ', serArr.map(x=>blsA.deserializeHexStrToPublicKey(x)))
    //console.log('SecretKey contribution SERIALIZE ', secKeyArr.map(x=>blsA.deserializeHexStrToSecretKey(x)))
    console.log('\n\n==================== RESULT ====================\n')

    let jsonVerificationVector=JSON.stringify(serializedVerificationVector),
    
        jsonSecretShares=JSON.stringify(serializedSecretKeyContribution),

        serializedId=signers[pubKeysArr.indexOf(myPubId)].id.serializeToHexStr()



    console.log(`Send this verification vector to all group members => ${jsonVerificationVector}`)
    console.log(`Send this secret shares to appropriate user(one per user) => ${jsonSecretShares}`)

    //console.log(`\n\nYour creds ${JSON.stringify(signers[pubKeysArr.indexOf(myPubId)])}`)
    console.log(`\n\nYour ID ${serializedId}`)

    return JSON.stringify({
    
        verificationVector:serializedVerificationVector,
        secretShares:serializedSecretKeyContribution,
        id:serializedId
    
    })
    
}



let verifyShareTBLS=async(hexMyId,hexSomeSignerSecretKeyContribution,hexSomeSignerVerificationVector)=>{

    //Deserialize at first from hex
    let someSignerSecretKeyContribution=blsA.deserializeHexStrToSecretKey(hexSomeSignerSecretKeyContribution)
    let someSignerVerificationVector=hexSomeSignerVerificationVector.map(x=>blsA.deserializeHexStrToPublicKey(x))
    let myId = blsA.deserializeHexStrToSecretKey(hexMyId)


    // Теперь когда нужный член групы получил этот secret sk,то он проверяет его по VSS с помощью verification vector of the sender и сохраняет его если всё ок
    const isVerified = dkg.verifyContributionShare(blsA,myId,someSignerSecretKeyContribution,someSignerVerificationVector)
 
    if(!isVerified) throw new Error(`Invalid share received from user with verification vector ${hexSomeSignerVerificationVector}`)
    else console.log(`Share ${hexSomeSignerSecretKeyContribution} valid - please,store it`) 
 
    //Store shares somewhere with information who send(which id) has sent this share for you

}

/**
 *   ## Derive public TBLS key from verification vectors of signers sides 
 *
 *   @param {Array<Array<string>>} hexVerificationVectors array of serialized verification vectors e.g. [ [hex1,hex2], [hex3,hex4], ...] where [hexA,hexB] - some verification vector 
 * 
 */
let deriveGroupPubTBLS=hexVerificationVectors=>{

    console.log(hexVerificationVectors.map(subArr=>
        
        subArr.map(x=>blsA.deserializeHexStrToPublicKey(x))
        
    ))

    const groupVvec = dkg.addVerificationVectors(hexVerificationVectors.map(subArr=>
        
        subArr.map(x=>blsA.deserializeHexStrToPublicKey(x))
        
    ))
    
    const groupPublicKey = groupVvec[0].serializeToHexStr()

    console.log(`Group TBLS pubKey is ${groupPublicKey}`)
    //blsA.deserializeHexStrToPublicKey(groupsPublicKey.serializeToHexStr())// - to deserialize

    return groupPublicKey

}


/*

На вход поступают данные вида

{

    hexMyId - id из первоначального массива signers из generateTBLS
    sharedPayload:[
        {
            verificationVector://VV of signer1 - array of hex values
            secretKeyShare://share received from signer1 - hex value
        },
        {
            verificationVector://VV of signer2
            secretKeyShare://share received from signer2
        },
        ...,
        {
            verificationVector://VV of signerN
            secretKeyShare://share received from signerN

        }
    ]

}

*/
let signTBLS=(hexMyId,sharedPayload,message)=>{

    //Derive group TBLS secret key for this signer
    let groupSecret=dkg.addContributionShares(
        
        sharedPayload
        
            .map(x=>x.secretKeyShare)//get only secretshare part
            .map(hexValue=>blsA.deserializeHexStrToSecretKey(hexValue))
        
    )

    console.log(`\n\nDerived group secret ${groupSecret.serializeToHexStr()}`)

    //The rest of t signers do the same with the same message

    return JSON.stringify({sigShare:groupSecret.sign(message).serializeToHexStr(),id:hexMyId})

}

/*

    signaturesArray - [ {sigShare:signedShare1,id:hexId1}, {sigShare:signedShare2,id:hexId2},... {sigShare:signedShareN,id:hexIdN} ]

*/
let buildSignature=signaturesArray=>{

    //Now join signatures by t signers
    const groupsSig = new blsA.Signature()
    
    let sigs=[],signersIds=[]

    signaturesArray.forEach(x=>{
        
        sigs.push(blsA.deserializeHexStrToSignature(x.sigShare))

        signersIds.push(blsA.deserializeHexStrToSecretKey(x.id))

    })

    groupsSig.recover(sigs,signersIds)

    console.log('Signature', groupsSig.serializeToHexStr())
  
    //blsA.deserializeHexStrToSignature(groupsSig.serializeToHexStr())

    return groupsSig.serializeToHexStr()

}

let verifyTBLS=(hexGroupPubKey,hexSignature,signedMessage)=>{

    let groupPubKey=blsA.deserializeHexStrToPublicKey(hexGroupPubKey),

        verified=groupPubKey.verify(blsA.deserializeHexStrToSignature(hexSignature),signedMessage)

    console.log('->    verified ?',verified)

    return verified

}

//==================================== ТЕСТИРОВАНИЕ ====================================

//3/4

let alice=generateTBLS(3,1,[1,2,3,4])
let bob=generateTBLS(3,2,[1,2,3,4])
let charlie=generateTBLS(3,3,[1,2,3,4])
let denis=generateTBLS(3,4,[1,2,3,4])


console.log(alice)
console.log(bob)
console.log(charlie)
console.log(denis)

alice=JSON.parse(alice)
bob=JSON.parse(bob)
charlie=JSON.parse(charlie)
denis=JSON.parse(denis)

let derivedPub=deriveGroupPubTBLS([alice.verificationVector,bob.verificationVector,charlie.verificationVector,denis.verificationVector])

console.log(derivedPub)


// {
//     verificationVector://VV of signer1 - array of hex values
//     secretKeyShare://share received from signer1 - hex value
// }

let aliceSig=signTBLS(alice.id,[
    {
        verificationVector:alice.verificationVector,
        secretKeyShare:alice.secretShares[0]

    },//own share
    {
        verificationVector:bob.verificationVector,
        secretKeyShare:bob.secretShares[0]
    },//data from bob
    {
        verificationVector:charlie.verificationVector,
        secretKeyShare:charlie.secretShares[0]
    },//from charlie
    {
        verificationVector:denis.verificationVector,
        secretKeyShare:denis.secretShares[0]
    },//from denis

],'HELLO KLYNTAR')

console.log(`Alice sigPart is ${aliceSig}`)

//Do the same for the rest 2 signers(Bob and Charlie)
let bobSig=signTBLS(bob.id,[
    {
        verificationVector:bob.verificationVector,
        secretKeyShare:bob.secretShares[1]

    },//own share
    {
        verificationVector:alice.verificationVector,
        secretKeyShare:alice.secretShares[1]
    },//data from alice
    {
        verificationVector:charlie.verificationVector,
        secretKeyShare:charlie.secretShares[1]
    },//from charlie
    {
        verificationVector:denis.verificationVector,
        secretKeyShare:denis.secretShares[1]
    },//from denis

],'HELLO KLYNTAR')

console.log(`Bob sigPart is ${bobSig}`)

let charlieSig=signTBLS(charlie.id,[
    {
        verificationVector:charlie.verificationVector,
        secretKeyShare:charlie.secretShares[2]

    },//own share
    {
        verificationVector:bob.verificationVector,
        secretKeyShare:bob.secretShares[2]
    },//data from bob
    {
        verificationVector:alice.verificationVector,
        secretKeyShare:alice.secretShares[2]
    },//from alice
    {
        verificationVector:denis.verificationVector,
        secretKeyShare:denis.secretShares[2]
    },//from denis

],'HELLO KLYNTAR')

console.log(`Charlie sigPart is ${charlieSig}`)



//_______________________ Join sigShares _______________________

let finalSig=buildSignature([
    JSON.parse(aliceSig),JSON.parse(bobSig),JSON.parse(charlieSig)
])
//signaturesArray - [ {sigShare:signedShare1,id:hexId1}, {sigShare:signedShare2,id:hexId2},... {sigShare:signedShareN,id:hexIdN} ]

console.log(`Builded signature is ${finalSig}`)

//_______________________ Verification _______________________


console.log(verifyTBLS(derivedPub,finalSig,'HELLO KLYNTAR'))

// let verificationVector = ["85de76c71640bd43d43bb904da358148a4042e5c24380b59ce9cb1a2c813100030922fe76eab63455b8f9254da8f497d116255bc41bc033d8424e08a28a57614","23075d8f8712fed159338e5c40c93b77a4b3e8abfd26c283b0e72d2db657981539a93e12c9d0f9ed9c5e24e26f63df7903a079b1a5bcd5b275ca6c2adbebcf1d","d61cf280c8179be8ad69787e62471c45e8237a1a840788b55313443c227f5a225bf844ecc59334996881bc85716ee870c2a0982e6802971ce7f21efeca6f6e17"]

// let shares = ["cbd16f43c655b74bbdfdea68a9e4bde99fef46650e44ee7374cc80003032e804","a74da185d51f2ccae50a6e22cc92416ecba5f9cdb39c4182324e1e0c1e294e0e","f238037d801e725f26528f1bab092b587348c6db771131e35037aff565103913","f0e750e02c2082f7ef88e38a802a88c1f7837fb38da476d39dbae12a576ac10b"]
// let myId = '4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785451a'


// await verifyShareTBLS(myId,shares[0],verificationVector)





//==================================== ТЕСТИРОВАНИЕ ====================================





// let arrayOfId=[10314, 30911, 25411]

// let threshold=2 //попробуем 2/3

// await blsA.init()

// //1.Производим генерацию для трёх сторон
// //Они могут это делать приватно
// let [alice,bob,charlie]=arrayOfId.map(id => {

//     const sk = new blsA.SecretKey()
  
//     sk.setHashOf(Buffer.from([id]))
  
//     return {id:sk,recievedShares:[],arrId:id}

// })

// //Тут массив verification vectors. По одному для каждого подписанта
// const vvecs = []


// //Вот процесс генерации для Алисы,Боба и Чарли - они могут это делать приватно
// const {verificationVector:aliceVerificationVector,secretKeyContribution:aliceSecretKeyContribution} = dkg.generateContribution(blsA,[alice,bob,charlie].map(x=>x.id),threshold)
// console.log(aliceVerificationVector)

// let aliceSerArr=aliceVerificationVector.map(x=>x.serializeToHexStr())
// let aliceSecKeyArr=aliceSecretKeyContribution.map(x=>x.serializeToHexStr())

// //console.log('Verification Vector SERIALIZE ', serArr.map(x=>blsA.deserializeHexStrToPublicKey(x)))
// //console.log('SecretKey contribution SERIALIZE ', secKeyArr.map(x=>blsA.deserializeHexStrToSecretKey(x)))

// console.log(`\n\n+++Verification vector for Alice`)
// console.log(`VECTOR => ${JSON.stringify(aliceSerArr)}`)
// console.log(`SECKEY CONTRIB => ${JSON.stringify(aliceSecKeyArr)}`)

// //Verification vector можем публиковать - для каждого в группе. Только запоминать порядок индексов
     
// vvecs.push(aliceVerificationVector)

// // Теперь когда нужный член групы получил этот secret sk,то он проверяет его по VSS с помощью verification vector of the sender и сохраняет его если всё ок

// const aliceVerified = dkg.verifyContributionShare(blsA, alice.id,aliceSecretKeyContribution[0],aliceVerificationVector)
// const bobVerified = dkg.verifyContributionShare(blsA, bob.id,aliceSecretKeyContribution[1],aliceVerificationVector)
// const charlieVerified = dkg.verifyContributionShare(blsA, charlie.id,aliceSecretKeyContribution[2],aliceVerificationVector)

// if(!aliceVerified || !bobVerified || !charlieVerified) throw new Error('Invalid share for Alice')

// //После проверки складываем шары вместе
// alice.recievedShares.push(aliceSecretKeyContribution[0])
// bob.recievedShares.push(aliceSecretKeyContribution[1])
// charlie.recievedShares.push(aliceSecretKeyContribution[2])


// //++++++++++++++++++++++++ ТЕПЕРЬ ДЕЛАЕМ ТОЖЕ САМОЕ ДЛЯ БОБА


// //Вот процесс генерации для Алисы,Боба и Чарли - они могут это делать приватно
// const {verificationVector:bobVerificationVector,secretKeyContribution:bobSecretKeyContribution} = dkg.generateContribution(blsA,[alice,bob,charlie].map(x=>x.id),threshold)
// console.log(bobVerificationVector)

// let bobSerArr=bobVerificationVector.map(x=>x.serializeToHexStr())
// let bobSecKeyArr=bobSecretKeyContribution.map(x=>x.serializeToHexStr())

// //console.log('Verification Vector SERIALIZE ', serArr.map(x=>blsA.deserializeHexStrToPublicKey(x)))
// //console.log('SecretKey contribution SERIALIZE ', secKeyArr.map(x=>blsA.deserializeHexStrToSecretKey(x)))

// console.log(`\n\n+++Verification vector for Bob`)
// console.log(`VECTOR => ${JSON.stringify(bobSerArr)}`)
// console.log(`SECKEY CONTRIB => ${JSON.stringify(bobSecKeyArr)}`)

// //Verification vector можем публиковать - для каждого в группе. Только запоминать порядок индексов
     
// vvecs.push(bobVerificationVector)

// // Теперь когда нужный член групы получил этот secret sk,то он проверяет его по VSS с помощью verification vector of the sender и сохраняет его если всё ок

// const aliceVerified2 = dkg.verifyContributionShare(blsA, alice.id,bobSecretKeyContribution[0],bobVerificationVector)
// const bobVerified2 = dkg.verifyContributionShare(blsA, bob.id,bobSecretKeyContribution[1],bobVerificationVector)
// const charlieVerified2 = dkg.verifyContributionShare(blsA, charlie.id,bobSecretKeyContribution[2],bobVerificationVector)


// if(!aliceVerified2 || !bobVerified2 || !charlieVerified2) throw new Error('Invalid share for Bob')

// //После проверки складываем шары вместе
// alice.recievedShares.push(bobSecretKeyContribution[0])
// bob.recievedShares.push(bobSecretKeyContribution[1])
// charlie.recievedShares.push(bobSecretKeyContribution[2])




// //++++++++++++++++++++++++ ТЕПЕРЬ ДЕЛАЕМ ТОЖЕ САМОЕ ДЛЯ ЧАРЛИ


// //Вот процесс генерации для Алисы,Боба и Чарли - они могут это делать приватно
// const {verificationVector:charlieVerificationVector,secretKeyContribution:charlieSecretKeyContribution} = dkg.generateContribution(blsA,[alice,bob,charlie].map(x=>x.id),threshold)
// console.log(charlieVerificationVector)

// let charlieSerArr=charlieVerificationVector.map(x=>x.serializeToHexStr())
// let charlieSecKeyArr=charlieSecretKeyContribution.map(x=>x.serializeToHexStr())

// //console.log('Verification Vector SERIALIZE ', serArr.map(x=>blsA.deserializeHexStrToPublicKey(x)))
// //console.log('SecretKey contribution SERIALIZE ', secKeyArr.map(x=>blsA.deserializeHexStrToSecretKey(x)))

// console.log(`\n\n+++Verification vector for Charlie`)
// console.log(`VECTOR => ${JSON.stringify(charlieSerArr)}`)
// console.log(`SECKEY CONTRIB => ${JSON.stringify(charlieSecKeyArr)}`)

// //Verification vector можем публиковать - для каждого в группе. Только запоминать порядок индексов
     
// vvecs.push(charlieVerificationVector)

// // Теперь когда нужный член групы получил этот secret sk,то он проверяет его по VSS с помощью verification vector of the sender и сохраняет его если всё ок

// const aliceVerified3 = dkg.verifyContributionShare(blsA, alice.id,charlieSecretKeyContribution[0],charlieVerificationVector)
// const bobVerified3 = dkg.verifyContributionShare(blsA, bob.id,charlieSecretKeyContribution[1],charlieVerificationVector)
// const charlieVerified3 = dkg.verifyContributionShare(blsA, charlie.id,charlieSecretKeyContribution[2],charlieVerificationVector)

// if(!aliceVerified3 || !bobVerified3 || !charlieVerified3) throw new Error('Invalid share for Charlie')

// //После проверки складываем шары вместе
// alice.recievedShares.push(charlieSecretKeyContribution[0])
// bob.recievedShares.push(charlieSecretKeyContribution[1])
// charlie.recievedShares.push(charlieSecretKeyContribution[2])


// //==============================================================================

// // Теперь каждый подписант соединяет вместе все полученные секреты для получения
// // общего секрета используя который можно сгенерить валидную threshold подпись

// alice.secretKeyShare = dkg.addContributionShares(alice.recievedShares)
// bob.secretKeyShare = dkg.addContributionShares(bob.recievedShares)
// charlie.secretKeyShare = dkg.addContributionShares(charlie.recievedShares)

// console.log('\n\nTheir secrets in hex')
// console.log('Alice ',alice.secretKeyShare.serializeToHexStr())
// console.log('Bob ',bob.secretKeyShare.serializeToHexStr())
// console.log('Charlie ',charlie.secretKeyShare.serializeToHexStr())


// // Теперь соединяем verification vectors которые публиковали остальные участники
// // и получаем общий единый verification vector всей группы
// const groupsVvec = dkg.addVerificationVectors(vvecs)
// const groupsPublicKey = groupsVvec[0]

// console.log('Group key ',groupsPublicKey.serializeToHexStr())
// // let decodedPub=blsA.deserializeHexStrToPublicKey(groupsPublicKey.serializeToHexStr())

// //=============================Тестируем подписи
// const message = 'KLYNTAR'
// const sigs = []
// const signersIds = []

// //Пусть подписантами будут Алиса и Боб(без Чарли). Реализуем 2/3

// //Подписывает Алиса
// sigs.push(alice.secretKeyShare.sign(message))
// signersIds.push(alice.id)

// //Подпись Боба
// sigs.push(bob.secretKeyShare.sign(message))
// signersIds.push(bob.id)


// //Теперь соединяем подписи
// const groupsSig = new blsA.Signature()
    
// groupsSig.recover(sigs,signersIds)
  
// console.log('Signature', groupsSig.serializeToHexStr())
  
// let decSigna=blsA.deserializeHexStrToSignature(groupsSig.serializeToHexStr())
// // console.log('DECODED SIGNA ',decSigna)
  
// let verified = groupsPublicKey.verify(groupsSig,message)
// console.log('->    verified ?', verified)