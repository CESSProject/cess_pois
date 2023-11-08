# cess_pois

CESS proof of idle space is used to reduce the work pressure of TEE Worker and improve the efficiency of idle space certification.
CESS proof of idle space transfers the generation of idle files to storage nodes, and through a series of challenge-response interactive proof processes to ensure that storage nodes honestly generate and store idle files.

In the proof of idle space, the idle file generation algorithm requires storage nodes to spend a certain amount of time and space to calculate and store idle files. A file set contains 32 clusters, and each cluster contains 8 idle files. The idle files in the file set cannot be calculated in parallel, but multiple file sets can be generated at the same time. After generating a batch of idle files, the storage node needs to submit the merkel hash tree root of the files to the TEE Worker to commit to certify these idle spaces.

Then TEE Worker will challenge the storage nodes for these commitments. Storage nodes need to prove that these idle files are generated in a legal way, and we call this process Proof of File Commitment.If these commitments prove to be verified by TEE Worker, the CESS network will recognize that these corresponding idle spaces are valid.

Then, the consensus node may initiate a space proof challenge to the storage nodes of the whole network at any time. If the storage node passes the challenge, it proves that it continues to hold the promised idle space, and the CESS network will issue rewards to these honest storage nodes, which is similar to the storage proof of CESS.

We believe that providing more storage space is cheaper than providing higher computing power.At present, it takes at least an hour for a storage node to generate an idle file set, and the proof process only takes over a minute. The storage node cannot temporarily generate idle files and provide valid proofs in a short period of time, which constitutes the security basis of the proof of idle space.

## Verifier guide

The verifier is responsible for verifying the proof provided by the prover. In the actual CESS network, the verifier is served by TEE Worker.

### Init Verifier
Before using the verifier, it needs to be initialized first. 
Since the lightweight MHT is used in the verification process, the MHT object pool also needs to be initialized.
```go
// k,n,d respectively represent the number of layers of expanders, the number of nodes in each layer and the in-degree of each node.
// k,n,d are always set to 7, 1024*1024 and 64.
verifier:=pois.NewVerifier(k,n,d)

// init mht object pool to reduce memory allocation
// n is the number of nodes in each layer,HashSize indicates the size of each element,the default is 64 (bytes) Generally. 
tree.InitMhtPool(n,expanders.HashSize)
```

### Register Storage Miner

The verifier needs to keep information about every storage miner it interacts with.
So before using Proof of Space, you need to register miners.
```go
//first, you need to check whether the miner is registered
ok:=verifier.IsLogout(minerID)
//ok means the miner is not registered or has left
if ok{ 
    // key is cess_pos_demo.acc.RsaKey,be created by tee worker first.
    //minerID is storage miner's accountId,it is a byte slice
    //acc , front and rear are storage miner's info from chain
    verifier.RegisterProverNode(minerID,key,acc,front,rear)
}

```

### PoIS setp 1:Receive Commits

first, receive idle file commits from a storage miner.
```go
//commits is a commits set of pois.CommitProof slice structure form miner
//commits can be transmitted using any communication protocol, and are generally serialized into a json byte sequence.
//Therefore, the received data needs to be decoded first and then handed over to the verifier for storage.
err:=verifier.ReceiveCommits(minerID,commits)
if err!=nil{
    //error handling code...
}

//if everythings is be ok,you need to response ok to miner.
// ...
```

### POIS setp 2:Generate Commit Challenges

After receiving the commits, it is necessary to generate commitchallenges to the storage miner, 
this step is to prove that the idle file commit by the miner is valid.
```go

chals, err := verifier.CommitChallenges(minerID)
if err!=nil{
    //error handling code...
}
// send chals to minner,chals is a slice of int64 slice,like [][]int64
// chals[i] represents a idle file commit challenge,including chals[i][0]=cluster,chals[i][1..9]=NodeIndex(last 9 layer),
// chals[i][j]=(node(j-1)'s parent node) when j>9
```

### POIS setp 3:Verify Commit Proofs

The verifier needs to verify the commit challenges proof submitted by the storage miner.
```go
//commitProofs, accProof, err := prover.ProveCommitAndAcc(chals)

// chals is commit challenges generated by verifier before,commitProof is chals proof generated by miner.
// verifier need to compare chals's file and node index and commitProofs' in VerifyCommitProofs method.
err:=verifier.VerifyCommitProofs(minerID, chals, commitProof)
if err!=nil{
    //verification failed
    ////error handling code...
}
//verification success
//send ok to miner
```

### POIS step 4:Verify Acc Proof

If the commit proof verification is successful, the storage miner will submit the proof of acc.
```go
//commitProofs, accProof, err := prover.ProveCommitAndAcc(chals)

//chals is commit challenges generated by verifier before,accproof is generated by miner.
err = verifier.VerifyAcc(minerID, chals, accProof)
if err != nil {
	//verification failed
    ////error handling code...
}
//verification success,commit verify be done,verifier will update miner Info in VerifyAcc method.
//send ok to miner
```

### POIS step 5:Generate Space Proof

This work will be performed by CESS Node, which is compatible with proof of storage.
But when testing you can mock the execution.
```go
//num is the number of space challenges in one idle file you want
//The num value has been specified as log2(n), defined in pois.SpaceChals
spaceChals, err := verifier.SpaceChallenges(num) //or verifier.SpaceChallenges(pois.SpaceChals)
if err!=nil{
    //error handling code...
}
//send spaceChals to miner,spaceChals same as commit chals,but one idle file just one node in last layer be challenged
```

### POIS step 6:Verify Space Proof

Verify the proof of space challenges submitted by the Storage Miner
```go
// spaceProof, err := prover.ProveSpace(spaceChals)

//spaceProof generated by miner, and pNode:=NewProverNode(minerID,acc,front,rear)
//Please do not use RegisterProverNode method to create pNode, because the proof of space may be performed at the same time as the proof of commits,
// and the miner parameters used in the proof of space should be consistent with the chain, so both acc, front and rear come from chain
err = verifier.VerifySpace(pNode, spaceChals, spaceProof)
if err!=nil{
     //error handling code...
}
//send ok to miner
// if err==nil,verify space success,the tee worker needs to report the result to the chain, 
//which can be implemented directly in rust later.
```
### POIS step 7:Verify Deletion Proof

Need to replace idle files with enough space every time user files are stored, even if there is enough unused space,in this way, the user can perceive the change of space,
and the verifier needs to verify that the new accumulator is obtained by deleting the specified file from the previous accumulator.
```go

//delProof read from chProof,
err = verifier.VerifyDeletion(minerID, delProof)
if err!=nil{
    //error handling code...
}
//send ok to miner
```

### Others
Why do we use complicated storage node registration and exit processes?
There are three reasons:
1. This can support the storage node to complete a certain number of commitment proofs before submitting the new accumulator and pois status to the blockchain, saving transaction costs;
2. The memory space of the verifier can be saved after the storage node exits;
3. Through continuous registration and exit, the state information of storage nodes, verifiers and blockchains can be kept consistent in time;
When a storage miner request for logout, the verifier needs to perform the following operations:
1. Call the exit method to get the current acc, front and rear of the storage miner
```go
acc,front,rear:=verifier.LogoutProverNode(minerID)
```
2. Sign acc, front, rear and return to storage miner;The specific details of the signature need to be negotiated with storage miners and chain nodes in the future.

*When the storage miner requests to delete idle files and the verification passes, you need to actively exit the miner and return the signature*

## Prover guide

The prover is responsible for generating idle space and submitting proofs to the verifier. This role is usually played by storage nodes.

### Init Prover

A storage node needs to uniquely hold a certifier object in any life cycle.When using Proof of Space for the first time, the prover object needs to be initialized. Under normal circumstances, the storage node will not stop the service, but when there is an unexpected situation such as downtime, you can create a new certifier object and restore it.

```go
// k,n,d and key are params that needs to be negotiated with the verifier in advance.
// minerID is storage node's account ID, and space is the amount of physical space available(MiB)
prover, err := pois.NewProver(k, n, d, minerID,space)
if err != nil {
    //error handling code...
}

//Please initialize prover for the first time
err=prover.Init(key)
if err != nil {
    //error handling code...
}

//If it is downtime recovery, call the recovery method.front and rear are read from minner info on chain
err=prover.Recovery(key,front,rear)
if err != nil {
    //error handling code...
}

// Run the idle file generation service, it returns a channel (recorded in the prover object), 
// insert the file ID into the channel to automatically generate idle files.
// The number of threads started by default is pois.MaxCommitProofThread(he number of files generation supported at the same time)
prover.RunIdleFileGenerationServer(pois.MaxCommitProofThread)
```
### POIS step 1:Generate Idle Files

Generate a single idle file set, note that this method is blocking and may return an error.
```go
err = prover.GenerateIdleFileSet()
if err != nil {
    // error handling code ...
}
```

If you want to increase the generation speed of idle files, you can use multi-threading method to generate multiple sets of idle files at the same time.

```go
err = prover.GenerateIdleFileSets(num) //num is number of thread you want
if err != nil {
    // error handling code ...
}
```

Be careful not to let the number of threads exceed the number of your CPU cores, otherwise it will be inefficient, and considering that you have to run other services, it is recommended not to exceed half of the number of CPU cores. In addition, each thread will occupy about 1.75G of memory, please pay attention to whether your hardware resources are sufficient.

### POIS step 2:Submit File Commits

The idle file commitment is used to declare to the verifier the free space to be certified.
``` go
// GetCommits method read file commits from dir storaged idle files. You need to submit commits to verifier.
commits, err := prover.GetCommits()
if err != nil {
    //error handling code...
}
```
To improve certification efficiency, you can generate a separate thread to perform steps 2 and 3 independently of idle file generation. 
At this point, the following method can be polled to know whether enough idle files have been generated to submit the certification.
``` go

for !prover.CommitDataIsReady(){
    
    time.Sleep(time.Second*30)
}

```

### POIS step 3:Prove Commits and ACC

After receiving the idle file commits of the storage node, the verifier will initiate a commitment challenge to it, and the storage node needs to submit the file commit proofs and accumulator proof as a response to the challenge.
```go
//The commit challenge is generated by the verifier (TEE Worker)
//chals, err := verifier.CommitChallenges(minerID, left, right)

commitProofs, accProof, err := prover.ProveCommitAndAcc(chals)
if err != nil {
    //error handling code...
}
if err == nil && commitProofs == nil && accProof == nil {
    //If the results are all nil, it means that other programs are updating the data of the prover object.
}
// send commitProofs and accProof to verifier and then wait for the response
```
The storage node needs to update the prover status according to the verification result of the verifier.
```go
// If the challenge is successful, update the prover status, fileNum is challenged files number, 
// the second parameter represents whether it is a delete operation, and the commit proofs should belong to the joining files, so it is false
err = prover.UpdateStatus(fileNum, false)
if err != nil {
    //error handling code...
}

// If the challenge is failure, need to roll back the prover to the previous status,
// this method will return whether the rollback is successful, and its parameter is also whether it is a delete operation be rolled back.
ok:=prover.AccRollback(false)
```

In the current version, a free space certification process can certify 16GiB free space for storage nodes. After the certification is completed, the storage node needs to end the session (logout) to the TEE Worker, and the TEE Worker will return the signature of the latest pois status. The storage node can submit the signature as evidence to the chain to make CESS recognize the newly certified free space.

It is supported to generate and delete idle files at the same time, but it needs to be serialized when updating the accumulator, so please update the status (use `prover.UpdateStatus(...)`) in time after completing the commitment challenge verification to prevent the deletion proof from being blocked.

### POIS step 4:Prove Space

The storage node needs to prove the space proof challenge of the consensus node from time to time to prove that it has persistently held the commited idle space.
```go
//The space challenge is generated by the chain node(consensus node)
//spaceChals, err := SpaceChallenges(minerID, fileNum)

// ProveSpace receives a space challenges parameter (which label of every files are included), and returns a challenge proofs, which may be error
// you can use left and right to complete proof of space challenges in batches,left>front,starting from front+1,and right<=rear+1.
// Please note that after each commit, in the new proof of space, left must be the right of the previous commit,such as (1,3),(3,5),(5,10)...
spaceProof, err := prover.ProveSpace(spaceChals,left,right)
if err != nil {
    //error handling code...
}
//send spaceProof to verifier and wait for the response, but the space challenge didn't change any state, so no update is required based on the response
```
*Note:*
Whenever you complete a batch of space proof challenge, you need to calculate the hash value of the proof data, calculate the total hash with the hash values of all proof batches as content (Arrange splicing in order), and submit the total hash value to the blockchain as proof of completion.

When the space proofs of all idle files are verified, the verifier will return the signature of the verification result, and you needs to submit the result and signature to the blockchain.Please submit in time to avoid overtime penalty.

### POIS step 5:Prove Deletion

When storing new user files, file deletion proof is required. The latest proof of space adopts queue model, deleting elements from the front and inserting elements from the rear, so the insertion and deletion of idle files do not conflict, they can be performed concurrently, but the priority of deletion is higher than that of insertion.
```go
//ProveDeletion passes in number of file blocks (the file block size is defined in pois.FileSize, generally 64MiB),
//so you first need to calculate how many file blocks the user file occupies, and call this method with this value as a parameter.
//The method returns a deletion proof channel and an error channel, because the deletion process has a lot of work and is asynchronous, you need to monitor the deletion result.
chProof, Err := prover.ProveDeletion(num)
var (
    delProof *pois.DeletionProof
    err error
)
select {
case err = <-Err:
    //error handling code...
case delProof := <-chProof:
    break
}

//If the deletion proof is not empty, it needs to be sent to the verifier
// send delProof to verifier

//if failed to verify delProof, you need to roll back status
prover.AccRollback(true) //If the parameter is set to true, it means the rollback of the deletion operation.

```
Please note that the verifier will return the signature of the new state after verifying the proof is successful, you need to submit the new state to the blockchain every time the deletion proof is successfully verified.When the transaction is sent successfully, you also need to call the `prover.UpdateChainState(num,true)` and `` method in time to update the local state.The precautions here are the same as before.


Please note that the space discussed here is a logical space, please provide a reasonable logical idle space for the storage node when using the space proof to prevent unnecessary errors.And when the user's file is less than 64M*256 (assuming that the file block size stipulated by the space proof is 64M), the minimum space needs to be 64M\*256\*2=16G. Because additional space is needed to store intermediate data during idle space certification, the minimum space is about twice as large. In addition, when you enable multi-threading to generate idle files, the minimum space required needs to be multiplied by the thread quantity. Of course, you can also adjust the number of threads in time to make use of the last remaining small space.

Finally, due to the need to store accumulators, cache intermediate results of proof of space, and cache user files, you need to reserve enough external space instead of declaring all physical space as logical space for proof of space.
