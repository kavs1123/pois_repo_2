## CS8.401: Principles of Information Security

# Programming Assignments

### Comprehensive Specication Explanation


- 1 Prelude: The Cryptographic Universe and the Great Clique Contents
   - 1.1 Motivation
   - 1.2 The Cryptographic Primitive Hierarchy
   - 1.3 Note
   - 1.4 Concrete Instantiations
   - 1.5 The No-Library Rule.
   - 1.6 Security Notions Roadmap
- 2 Part 0: The Minicrypt Clique Web Explorer (Interactive Component)
   - 2.1 The Core Problem the App Must Solve
   - 2.2 Layout Specication
   - 2.3 The Under-the-Hood Requirement (Critical).
   - 2.4 Supported Reductions and the Routing Table
   - 2.5 PA #0 | What You Must Implement
   - 2.6 PA #1 | One-Way Functions & Pseudorandom Generators.
   - 2.7 PA #2 | Pseudorandom Functions via GGM Tree.
   - 2.8 PA #3 | CPA-Secure Symmetric Encryption.
   - 2.9 PA #4 | Modes of Operation
   - 2.10 PA #5 | Message Authentication Codes (MACs)
   - 2.11 PA #6 | CCA-Secure Symmetric Encryption.
- 3 Part II: Hashing and Data Integrity
   - 3.1 PA #7 | Merkle-Damgard Transform
   - 3.2 PA #8 | DLP-Based Collision-Resistant Hash Function.
   - 3.3 PA #9 | Birthday Attack (Collision Finding)
   - 3.4 PA #10 | HMAC and HMAC-Based CCA-Secure Encryption
- 4 Part III: Public-Key Cryptography (Cryptomania)
   - 4.1 PA #11 | Diffie-Hellman Key Exchange (SKE)
   - 4.2 PA #12 | Textbook RSA.
   - 4.3 PA #13 | Miller-Rabin Primality Testing.
   - 4.4 PA #14 | Chinese Remainder Theorem & Breaking Textbook RSA
   - 4.5 PA #15 | Digital Signatures.
   - 4.6 PA #16 | ElGamal Public-Key Cryptosystem
   - 4.7 PA #17 | CCA-Secure PKC
- 5 Part IV: Secure Multi-Party Computation (MPC)
   - 5.1 PA #18 | Oblivious Transfer (OT)
   - 5.2 PA #19 | Secure AND Gate.
   - 5.3 PA #20 | All 2-Party Secure Computation (Yao / GMW)
- 6 Summary: The Full Reduction Chain


## 1 Prelude: The Cryptographic Universe and the Great Clique Contents

### 1.1 Motivation

Modern cryptography is built on a beautifully minimal foundation: the existence of aOne-Way
Function (OWF). From this single computational assumption|that some functions are easy
to compute but hard to invert|we can deriveevery symmetric cryptographic primitive used
in practice. This chain of reductions is both the theoretical backbone of our assignments and a
profound statement about what computation can and cannot do.

### 1.2 The Cryptographic Primitive Hierarchy

The diagram below shows thecomplete reduction graphamong the primitives we study. An
arrowA!B means \AimpliesB" (i.e., givenAwe can constructB). The double-headed
arrows show the remarkableequivalencesat the core of Minicrypt.

### 1.3 Note

We have added comprehensive explanation of each programming assignment to avoid any con-
fusion and assist easy implementations. If you have any doubts, feel free to reach out to your
respective TAs.


```
Minicrypt Clique
```
```
OWF
One-Way Function
```
```
PRG
Pseudorandom Gen.
```
```
OWP
One-Way Permutation
```
```
PRF
Pseudorandom Func.
```
```
PRP
Pseudorandom Perm.
```
```
MAC
Message Auth. Code
```
```
CRHF
Coll.-Res. Hash
```
HMAC
Hash-based MAC

```
CPA-Enc
Chosen-PT Secure
```
```
CCA-Enc
Chosen-CT Secure
```
```
PKC
Public-Key Crypto
```
```
Digital Sig.
Non-repudiation
```
```
CCA-PKC
Active-Sec. PKC
```
```
OT
Oblivious Transfer
```
```
Secure AND Secure XOR(free)
```
```
All 2-Party
MPC
```
```
AES
(concrete PRP/PRF)
```
```
DLP
(concrete OWF/OWP)
```
```
GGM
```
```
GGM
```
```
HMAC
```
```
MAC$CRHF
```

The Minicrypt Equivalence Theorem

The following areequivalent(each implies all others):

```
 One-Way Functions (OWFs) exist
 Pseudorandom Generators (PRGs) exist
 Pseudorandom Functions (PRFs) exist
 One-Way Permutations (OWPs) exist
 Pseudorandom Permutations (PRPs) exist
 Secure Message Authentication Codes (MACs) exist
 Collision-Resistant Hash Functions (CRHFs) exist (linked via HMAC)
 HMAC exists (bridges CRHF$MAC)
```
This is theMinicrypt Clique. Proving any one of these exists immediately gives you all
the others|and your assignments will implement every step of this chain. Note that
construction of all edges may not be possible since some might be open problems. Try
to complete the ones that are already known.

Note on CRHF and HMAC:The classical Minicrypt clique consists of the rst six
primitives. CRHF and HMAC join the clique through HMAC's security proof: if the
hash's compression function is a PRF (which our PA#8 DLP-based hash satises), then
HMAC is a secure MAC (CRHF)MAC). The reverse direction holds because a secure
MAC used as a Merkle-Damgrd compression function gives a CRHF (MAC)CRHF).
This bidirectional link is demonstrated concretely in PA#9 (birthday attack, establish-
ing the security 
oor of any CRHF) and PA#10 (HMAC construction + CCA-secure
encryption).

Implementation Requirement: Bidirectional Reductions (All Clique Primi-
tives)

The equivalences in the Minicrypt Clique arebiconditional:A,B, not merelyA)B.
Rule:You are required to implement a primitiveif and only ifyou also implement the
reduction inbothdirections for every adjacent pair in the clique. For each pair (A; B)
below you must demonstrate: (i) how toconstructBfromA, and (ii) how breakingB
would allow you tobreakA(i.e., a reduction in the reverse direction). The complete set
of required bidirectional implementations is:

OWF,PRG

```
Forward OWF)PRG: HILL/iterative construction | applyf repeatedly with
hard-core predicateb; outputb(f^0 (x))∥b(f^1 (x))∥
BackwardPRG)OWF: Any PRGGis immediately a OWF. Denef(s) =G(s);
inversion offwould invertG, recovering the seed and breaking pseudorandomness.
```
OWF,OWP

```
Forward OWF)OWP: Any OWF on a domain with efficiently samplable pre-
images can be converted to a OWP (e.g., DLP:f(x) = gxmodpis a OWP on
Zq).
BackwardOWP)OWF: Immediate | a OWP is a special case of a OWF (bijective,
hence also hard to invert).
```
PRG,PRF


```
ForwardPRG)PRF: GGM tree construction. GivenG:f 0 ; 1 gn!f 0 ; 1 g^2 n, dene
Fk(b 1 bn) =Gbn(Gb 1 (k)).
BackwardPRF)PRG: DeneG(s) =Fs(0)∥Fs(1). IfGwere distinguishable from
random, the distinguisher could be used to break the PRF.
```
#### OWP,PRG

```
Forward OWP)PRG: Any OWP with a hard-core predicatebyields a PRG:
G(x) = (f(x); b(x)), expanding by one bit per application.
Backward PRG)OWP: A length-preserving PRG is itself a OWP (it must be
injective and hard to invert, hence a permutation on its range).
```
PRF,PRP

```
Forward PRF)PRP: Luby-Rackoff construction. Apply three or four rounds of
a Feistel network using the PRF as the round function: a 3-round Feistel yields a
secure PRP; a 4-round Feistel yields a securestrongPRP (indistinguishable even
from an adversary with inversion queries).
Backward PRP)PRF: A PRP over a super-polynomially large domain is com-
putationally indistinguishable from a PRF (by the PRF/PRP switching lemma).
Concretely, AES (a PRP) is used directly as a PRF in CTR, OFB, and GCM.
```
#### PRF,MAC

```
ForwardPRF)MAC: Mack(m) =Fk(m). If the MAC were forgeable, the forger
distinguishesFkfrom a random function, breaking PRF security.
BackwardMAC)PRF: A secure EUF-CMA MAC on uniformly random messages
is a PRF. Use the MAC oracle as a PRF oracle; unforgeability implies pseudoran-
domness of outputs.
```
PRP,MAC(via PRF as bridge)

```
Forward PRP)MAC: Use the PRP directly as a PRF (switching lemma), then
apply PRF)MAC above. Concretely: AES-CMAC and CBC-MAC both use a
block cipher (PRP) as the underlying primitive.
BackwardMAC)PRP: Via MAC)PRF (above) and then PRF)PRP (Luby-
Rackoff).
```
OWP,PRF(completing the clique)

```
ForwardOWP)PRF: OWP)PRG (above) then PRG)PRF (GGM).
BackwardPRF)OWP: PRF)PRP (Luby-Rackoff); a PRP onf 0 ; 1 gnkeyed by
kgives OWPf(k) = PRPk(0n).
```
CRHF,HMAC

```
Forward CRHF)HMAC: Given a hash functionHbuilt on a PRF-secure com-
pression function (e.g., your PA#8 DLP hash), dene HMACk(m) = H
```
#### (

```
(k
opad)∥H((kipad)∥m)
```
#### )

. Security holds because the inner hash acts as a PRF
on the message, and the outer hash acts as a PRF on the inner hash output.


```
Backward HMAC)CRHF: Fix a keykand deneH′(m) = HMACk(m). This
keyed function is collision-resistant (any collision would constitute a MAC forgery).
More generally, use the HMAC compression step as the compression function in a
new Merkle-Damgrd hash.
```
```
HMAC,MAC(HMAC joins the MAC equivalence class)
```
```
ForwardHMAC)MAC: HMAC is a secure EUF-CMA MAC when the compression
function is a PRF. This is exactly what PA#10 implements.
BackwardMAC)HMAC: Any secure PRF-based MAC can be cast in the HMAC
double-hash structure by treating the MAC as the inner compression step. The
HMAC structure is therefore not a special-case construction but the natural PRF-
based MAC for hash-structured primitives.
```
```
CRHF,MAC(the full bridge, via HMAC)
```
```
ForwardCRHF)MAC: CRHF)HMAC)MAC (two steps above). Concretely:
your PA#8 DLP hash)PA#10 HMAC)PA#10 CCA-secure encryption.
BackwardMAC)CRHF: A secure MAC serves as a collision-resistant compression
function (any collision in the MAC output is a forgery). Apply the Merkle-Damgrd
transform (PA#7) to get a full CRHF.
```
```
This bidirectionality is what makes these six primitives aclique, not merely a chain. Sub-
mitting only forward constructions earns partial credit; full credit requires both directions
for every pair you implement.
```
### 1.4 Concrete Instantiations

In practice we use two primary workhorses:

```
 AES (Advanced Encryption Standard):A concrete, highly optimizedPRP(and by
extension PRF) based on the algebraic structure of GF(2^8 ). Whenever an assignment
asks for a \generic PRF," you may plug in AES.
 Discrete Logarithm Problem (DLP):The assumption that computing logghin a
cyclic groupGis computationally hard. This gives us a concrete OWF/OWP, and under-
pins Diffie-Hellman, ElGamal, and the DLP-based hash function.
```
### 1.5 The No-Library Rule.

```
Global Policy: No External Cryptographic Libraries
```
```
Every cryptographic primitive used in any programming assignmentmust be your
own prior implementation. You maynot substitute a library (e.g. PyCryptodome,
OpenSSL, BouncyCastle,cryptography, Java'sjavax.crypto, etc.) at any point in the
dependency chain.
Specically:
```
```
 If PA#18 (OT) requires a PKC, you must supply your own implementation from
```

```
PA#12 or PA#16 | notimport rsaor equivalent.
 If PA#6 or PA#10 (CCA-Enc) require a MAC, you must supply your own from
PA#5 (for PRF-MAC) or PA#10 (for HMAC) | not HMAC fromhashlibor any
other library.
 If PA#10 (HMAC) requires a hash function, you must supply your ownDLPHash
from PA#8 | not SHA-256 or any standard library hash.
 If PA#4 (Modes) requires a block cipher, you must supply your own PRF/PRP
from PA#2, or your own AES implementation | not a library AES call.
 PA#20 (MPC) must be built end-to-end using your PA#19 (Secure AND) and
your PA#18 (OT) | not a garbled-circuit library.
```
```
The one permitted exception:You may use standard library functions forarbitrary-
precision integer arithmetic(e.g. Python's built-inint, Java'sBigInteger) and forOS-
level randomness(os.urandom,SecureRandom). Everything above raw integers and ran-
dom bytes must be your own code.
Why this rule exists:The entire point of these assignments is to trace the reduction
chain in code. If you substitute a library primitive at any node, you break the chain
and defeat the purpose of the exercise. The dependency graph below makes the required
lineage explicit.
```
### 1.6 Security Notions Roadmap

```
OTP
Perfect (info-theoretic)
```
```
CPA-Secure
Comp. indistinguishable
```
```
CCA1-Secure
Non-adaptive
```
```
CCA2-Secure
Fully adaptive
```
```
relax + integrity adaptive
```
```
requiresjkj=jmj PRF-based Encrypt-then-MAC
```

## 2 Part 0: The Minicrypt Clique Web Explorer (Interactive Component)

```
What This Assignment Is and Why It Exists Here
```
```
The programming assignments in Parts I{IV ask you to implement each Minicrypt primi-
tive on the command line. This section adds a complementary deliverable: aReact web
applicationthat makes every reduction in the cliquevisual, interactive, and traceable
with real data.
The app does not replace the terminal implementations. Itcallsthem. Its purpose is to
force you to think about a question the terminal assignments can obscure:where does
the concrete data actually come from?Every abstract reduction in the clique says
\given an oracle for primitiveA, construct primitiveB." But an oracle is not code. You
have to pick a concrete function|AES or DLP|and trace how that function 
ows all
the way up the chain toB.
Placement: This section is described here, in the Prelude, because the app is built
incrementally as you complete Parts I{IV. You can stub out primitives you have not
yet implemented and ll them in as the course progresses. A fully working version is
expected by the nal submission deadline.
```
### 2.1 The Core Problem the App Must Solve

Consider the reduction PRG)PRF (the GGM construction). Abstractly, it says: given any
PRGG, deneFk(x) =Gxn(Gx 1 (k)). But to run this on actual data you need an actual
PRG. Where does it come from?

The answer is always one of two concrete starting points:

```
 AES| a concrete PRP/PRF. To get a PRG from AES: use AES as a PRF (PRP/PRF
switching lemma), then deneG(s) =Fs(0)∥Fs(1).
 DLP| a concrete OWF/OWP. To get a PRG from DLP: apply the hard-core-bit con-
struction (HILL), iteratingf(x) =gxmodpto extract pseudorandom bits.
```
In either case, reaching PRF requirestwo distinct legs:

1. Leg 1 (foundation!source primitive): Instantiate the source primitive from the
    concrete foundation. This is always done under the hood, regardless of which two clique
    members the user picks.
2. Leg 2 (source primitive!target primitive):Apply the abstract reduction. This is
    the visible operation on screen.

The web app makes both legs explicit, with data 
owing through each one.


```
Foundation
AES (PRP)orDLP (OWF)
```
```
Source PrimitiveA
e.g., PRG
```
```
Target PrimitiveB
e.g., PRF
```
```
Leg 1(Column 1)
Foundation!A
always under the hood
chosen by foundation toggle
```
```
Leg 2(Column 2)
A!B
visible on screen
chosen by primitive selectors
```
```
Leg 1
```
```
Leg 2
```
### 2.2 Layout Specication

The app has axed three-tier layout:

1. Top bar | Foundation selector:A toggle with two options:AES-128 (PRP)andDLP
    (gxmodp). Changing this toggle affects Column 1 entirely and re-runs all computations.
2. Two-column main area:

```
 Column 1 | \Build" panel (Leg 1: Foundation!Source PrimitiveA):
{ A dropdown: select thesource primitiveAfrom the clique (OWF, PRG, PRF,
PRP, MAC, CRHF, HMAC).
{ An input eld: enter a raw key or seed (hex string).
{ A step-through display: shows each sub-reduction from the foundation toA,
with the actual intermediate byte values at each step.
{ Example for AES + PRG: shows AES key!PRF Fk(0)∥Fk(1) = PRG output.
 Column 2 | \Reduce" panel (Leg 2: Source PrimitiveA!Target Prim-
itiveB):
{ A dropdown: select thetarget primitiveB(must differ fromA).
{ An input eld: enter the message or query to evaluate.
{ A step-through display: shows the reduction fromAtoB(e.g., GGM tree for
PRG!PRF), with real intermediate values.
{ The output of Column 1 is automatically piped as the concrete implementation
ofAused in Column 2.
```
3. Bottom panel | Reduction proof summary: A collapsible box showing the full
    chain: Foundation!A!B, the theorem names (HILL, GGM, Luby-Rackoff, etc.), and
    the security claim at each step.


```
Foundation: AES-128 (PRP) / DLP (gxmodp) CS8.401 Minicrypt Clique Explorer
Column 1: Build Source Primitive from Foundation
```
```
Source primitiveA: PRG▼
Input seed: a3f2... (hex)
AESk(0) =7f3a...
AESk(1) =c19b...
PRG(s)=7f3ac19b...
```
```
Column 2: Reduce Source to Target Primitive
```
```
Target primitiveB: PRF▼
Queryx: 1011 (bits)
GGM:G 1 (G 0 (k))
=G 1 (7f3a...)
PRFk(x)=88d4...
```
```
Reduction Chain Summary (click to expand)
AES (PRP)!switching lemmaPRF!G(s)=Fs(0)∥Fs(1) PRG!GGM tree PRF
Security: PRF-security of AES)PRG-security (negl. advantage))PRF-security (GGM thm.)
All intermediate values shown above are real outputs from your PA#1{#2 implementations.
```
### 2.3 The Under-the-Hood Requirement (Critical).

```
Architectural Rule: The Foundation Must Flow Through Column 1
```
```
Column 2 isnotallowed to call the foundation (AES or DLP) directly. It may only call
the source primitiveAthat Column 1 has constructed.
Concretely: if the user selects Foundation = AES, Source = PRG, Target = PRF:
```
```
 Correct: Column 1 buildsPRGusing AES under the hood. Column 2 receives a
PRGobject and runs GGM on it, never touching AES directly.
 Wrong: Column 2 calls AES directly to implement the GGM tree leaves. This
collapses the two legs into one and defeats the purpose.
```
```
This rule enforces the reduction structure: each primitive is a black box to the layer
above it. The same rule applies to all choices ofAandB.
```
### 2.4 Supported Reductions and the Routing Table

Not every pair (A; B) has a direct one-step reduction. The app must implement arouting
tablethat computes the shortest path in the clique graph and chains the reductions:


```
SourceA TargetB Reduction chain used
OWF PRG HILL hard-core-bit construction
OWF OWP DLP is already a OWP (identity for DLP foundation)
PRG PRF GGM tree
PRF PRP Luby-Rackoff 3-round Feistel
PRF MAC Mack(m) =Fk(m)
PRP MAC PRP/PRF switching lemma, then MAC
CRHF HMAC HMAC construction (PA#10)
HMAC MAC Direct (HMAC is a MAC)
Any Any Compose the above steps as needed
```
For backward reductions (B!A), the app also supports the reverse direction (bidirectional
mode toggle).

### 2.5 PA #0 | What You Must Implement

```
PA #0 | What You Must Implement
```
1. React app scaffold: Create a React app (Create React App or Vite) with the three-
    tier layout described above. Foundation toggle, two-column main area, and bottom
    proof panel. Styling is your choice but the layout must be clearly two-column.
2. Foundation layer: Implement two foundation modules:
     AESFoundation: wraps your PA#2 AES-based PRF. ExposesasOWF(),asPRF(),
       asPRP().
     DLPFoundation: wraps your PA#1 DLP-based OWF. Exposes asOWF(),
       asOWP().
    Both modules share a commonFoundationinterface so the rest of the app is agnostic.
3. Column 1 | Build panel: Given a Foundation and a target source primitiveA,
    compute and display the full chain Foundation!A, showing each intermediate value.
    Each step must display: the function applied, the input bytes (hex), and the output
    bytes (hex). The actual computation must call your existing PA implementations
    compiled to WebAssembly or via a local API |notreimplemented in JavaScript.
4. Column 2 | Reduce panel: Given the concrete instance ofAproduced by Column
    1 and a target primitiveB, compute and display the reductionA!Bstep by step.
    Column 2 must receiveAas a black box (a function object) and must not inspect its
    internals.
5. Routing table: Implementreduce(A, B, foundation)that returns the ordered list
    of reduction steps to chain. Handle all pairs listed in the table above. For unsupported
    pairs (e.g., CRHF!OWP), display a clear message explaining why no direct path
    exists in this direction and suggest using the bidirectional toggle.
6. Live data 
ow: When the user changes any input (foundation toggle, source/target
    primitive, key, message), all panels update in real time without a page reload.
7. Bidirectional mode: Add a toggle \Forward (A!B) / Backward (B!A)" that
    swaps the columns and shows the reverse reduction (e.g., MAC!PRF by querying
    the MAC as a PRF oracle and running the distinguishing game).
8. Proof summary panel: For each selected pair (A; B), display the formal security
    chain: which theorem justies each step, what the security reduction is (\if adversary
    breaksBwith advantageε, it breaksAwith advantageε′ε=q"), and the PA number


```
that implements each step.
```
9. Stub support: Primitives you have not yet implemented should show a \Not imple-
    mented yet (due: PA#N)" placeholder with a greyed-out step in the chain. The app
    must be fully runnable with any subset of primitives implemented.

PA #0 | Interactive Demo Deliverable

The scaffold itselfisthe demo for PA#0. Graders will open the app in a browser and
check:

```
 The foundation toggle (AES / DLP) is visible and switches without errors.
 Both columns render with their dropdowns and input elds.
 Selecting any primitive pair shows a \Not yet implemented" placeholder with the
correct PA number | not a blank or crash.
 The bottom proof panel opens/closes on click and displays the static reduction
chain text for the selected pair.
```
Toy parameters:No real crypto is needed for PA#0. Stub functions returning xed
hex strings are ne at this stage.


```
Intuition
Why start from scratch? A truly random One-Time Pad givesperfect (Shannon)
secrecy but demands a key as long as the message. The key insight of computational
cryptography is: we only need an adversary to becomputationallyindistinguishable from
random, not information-theoretically so. A short random seed fed into a PRG yields
apseudorandomstream that is indistinguishable from true randomness by any efficient
adversary. Upgrading to a PRF gives us indexed, non-sequential access, enabling MAC
and encryption. This is the bootstrapping miracle of Minicrypt.
```
### 2.6 PA #1 | One-Way Functions & Pseudorandom Generators.

One-Way Functions (OWFs)

```
Denition: One-Way Function
```
```
A polynomial-time computable functionf :f 0 ; 1 g! f 0 ; 1 g isone-wayif for every
PPT adversaryA:
Pr
```
#### [

```
A(1n; f(x)) 2 f^1 (f(x))
```
#### ]

```
negl(n)
wherex f 0 ; 1 gnuniformly at random.
```
Concrete OWFs to implement:

```
 Modular exponentiation (DLP):f(x) =gxmodpin a prime-order group.
```
```
 Integer factoring: f(p; q) =pqfor large primesp; q.
```
```
 AES as a compression OWF:f(k) = AESk(0^128 )k.
```
Pseudorandom Generators (PRGs)

```
Denition: PRG
```
```
A deterministic polynomial-time functionG:f 0 ; 1 gn!f 0 ; 1 gn+ℓ(n)(for anyℓ(n)>0) is
aPRGif for every PPT distinguisherD:
```
(^)
(^) s fPr 0 ; 1 gn[D(G(s)) = 1]r f 0 ;Pr 1 gn+ℓ(n)[D(r) = 1]
(^)
negl(n)
Construction of a PRG from a OWF(Hastad{Impagliazzo{Levin{Luby): Given OWFf
with hard-core predicateb(e.g., the Goldreich-Levin bit), dene:
G(x 0 ) =b(x 0 )∥b(x 1 )∥  ∥b(xℓ) wherexi+1=f(xi)


```
seeds
nbits
f f f 
```
```
b(x 1 ) b(x 2 ) b(x 3 )
```
```
x 0 x 1 x 2
```
```
output:n+ℓpseudorandom bits
```
```
Security Claim
```
```
Iffis a OWF with hard-core predicateb, thenGas constructed above is a secure PRG.
Security reduces to the hardness of invertingf.
```
```
PA #1 | What You Must Implement
```
1. OWF (choose one concrete instantiation):
     DLP-based:f(x) =gxmodp, with a safe primepand generatorgof prime-order
       subgroup.
     AES-based:f(k) = AESk(0^128 )k(Davies-Meyer-style).
     Your OWF must expose aevaluate(x)function and averifyhardness()demo
       (show that random inversion fails).
2. PRG from OWF(forward direction, PA#1a): Implement the iterative hard-core-
    bit construction. Given seeds 2 f 0 ; 1 gn, produce an output of length n+ℓfor
    user-speciedℓ.
3. OWF from PRG(backward direction, PA#1b): Show thatf(s) =G(s) is a OWF.
    Provide a brief written argument (code comment or README) and a demonstration
    that an adversary givenG(s) cannot recoversefficiently.
4. Statistical test suite:Run your PRG output through at least three NIST SP 800-
    tests: frequency (monobit), runs, and serial. Report pass/fail andp-values.
5. Interface:Your PRG must exposeseed(s),nextbits(n)so that PA#2 can con-
    sume it as a black box.

```
PA #1 | Interactive Demo Deliverable
```
```
Demo: Live PRG output viewer.In the web app, PA#1's demo panel shows:
```
```
 A hex input eld for the seeds(e.g., 16 bytes).
 A slider for output lengthℓ(8{256 bytes).
 Live output: as the user types or moves the slider,G(s) updates instantly.
 A \Randomness test" button that runs the frequency and runs tests and displays
pass/fail with a bar showing the bit ratio (50% ones expected).
```
```
Toy parameters: 64-bit seed, DLP group of order 230 or AES-128. Must run in
under 1 second.
```
### 2.7 PA #2 | Pseudorandom Functions via GGM Tree.

A PRFFk:f 0 ; 1 gn! f 0 ; 1 gnmaps an inputxto an output that is computationally indistin-
guishable from a truly random function, when the keykis secret.


The GGM Tree Construction

Given a length-doubling PRGG:f 0 ; 1 gn!f 0 ; 1 g^2 n, writeG(s) =G 0 (s)∥G 1 (s) (left and right
halves). Dene:
Fk(b 1 b 2 bn) =Gbn(Gbn 1 (Gb 1 (k)))

```
k
```
```
G 0 (k)
```
```
G 0 G 0
```
```
Fk(00)
```
```
0
Fk(01)
```
```
1
```
```
0
G 1 G 0
```
```
Fk(10)
```
```
0
Fk(11)
```
```
1
```
```
1
```
```
0
```
```
G 1 (k)
```
```
G 0 G 1
```
```
Fk(00)
```
```
0
Fk(01)
```
```
1
```
```
0
G 1 G 1
```
```
Fk(10)
```
```
0
Fk(11)
```
```
1
```
```
1
```
```
1
```
```
Depth-2 GGM tree forn= 2 input bits
```
```
PRF from PRG
Inputs:Keyk2f 0 ; 1 gn, queryx=b 1 bn2f 0 ; 1 gn
Algorithm:
```
1. Sets 0 k
2. Fori= 1 ton: setsi Gbi(si 1 )
3. Outputsn

```
Cost: nevaluations ofG; tree has 2n leaves total but only one root-to-leaf path is
computed per query.
```
Plugging in AES:For practical purposes, AES-128 is already a highly efficient PRP/PRF.
You may useFk(x) = AESk(x) directly, bypassing the GGM construction.


```
Security Claim
```
```
IfGis a secure PRG, then the GGM construction yields a secure PRF. Concretely: any
PPT adversary makingqqueries toFkcannot distinguish it from a random oracle with
advantage greater than negl(n).
```
```
PA #2 | What You Must Implement
```
1. GGM PRF from your PA#1 PRG(forward direction, PA#2a): Implement the
    depth-nGGM binary tree. Keyk2f 0 ; 1 gn, inputx2f 0 ; 1 gn; follow the root-to-leaf
    path dened by the bits ofx, applyingG 0 orG 1 at each level. Output the leaf value
    Fk(x).
2. PRG from PRF(backward direction, PA#2b): ImplementG(s) =Fs(0n)∥Fs(1n)
    as a length-doubling PRG. Show this produces pseudorandom output by running it
    through the same statistical test suite as PA#1.
3. AES plug-in: Implement an alternative PRF using AES-128 directly: Fk(x) =
    AESk(x) (your own AES or the OS primitive as the one allowed exception). Show that
    substituting AES for your GGM PRF produces functionally identical results down-
    stream.
4. Distinguishing game demo: Write a test that queries your PRF onq= 100 random
    inputs and a truly random function on the same inputs, and conrms no statistical
    difference (supporting PRF security empirically).
5. Interface:ExposeF(k, x)so that PA#3, PA#4, and PA#5 can use it as a drop-in.

```
PA #2 | Interactive Demo Deliverable
```
```
Demo: GGM tree visualiser.In the web app:
```
```
 Input: keyk(hex) and a queryx(bit string of lengthn8).
 Display: the GGM binary tree up to depthn, with each node showing its value in
hex. The path taken for queryxis highlighted in blue; inactive nodes are greyed
out.
 The leaf value is labelled \Fk(x) =" and shown in a prominent output box.
 Changing any input bit ofxre-highlights the path instantly, showing how a 1-bit
change in the query produces an uncorrelated output.
```
```
Toy parameters: n= 4{8 bits (tree depth), so the diagram stays readable. AES or
your PRG as leaves.
```
### 2.8 PA #3 | CPA-Secure Symmetric Encryption.

```
Intuition
Chosen-Plaintext Attack (CPA):The adversary can encrypt arbitrary messages of
their choice (e.g., by sending them to an encryption oracle). CPA security demands
that the adversary cannot learn anything about which of two equal-length messages was
encrypted, even after seeing polynomially many encryptions.
```

Standard CPA-Secure Construction

```
Enc-then-PRF Construction
Key:k2f 0 ; 1 gn
Encryptionofm2f 0 ; 1 gn:
```
1. Sampler f 0 ; 1 gnuniformly at random (fresh each encryption).
2. OutputC=⟨r; Fk(r)m⟩

```
DecryptionofC=⟨r; c⟩:
```
1. Computem=Fk(r)c

```
r f 0 ; 1 gn Fk
```
```
plaintextm
```
```
r  ciphertextC=⟨r; Fk(r)m⟩
Fk(r)
```
```
rincluded inC
```
```
Security Claim
```
```
The scheme above is CPA-secure ifFkis a secure PRF. The key is thatrisfresh and
randomfor each encryption; reusingrbreaks security catastrophically.
```
CPA Security Game

```
Challenger AdversaryA
Enc(mi) oracle
```
```
m 0 ; m 1 (challenge)
```
```
C= Enc(mb),b f 0 ; 1 g
```
```
Enc(mi) oracle (cont.)
```
```
guessb′
```
```
Awins ifb′=b
```
```
PA #3 | What You Must Implement
```
1. CPA-secure encryption scheme: ImplementEnc(k, m)andDec(k, c)using the
    constructionC=⟨r; Fk(r)m⟩whereris freshly sampled each call. YourFkmust
    be your own PRF from PA#2 (not a library).


2. Multi-block support: Extend to messages longer than one block by applying the
    PRF tor; r+1; r+2; : : :(counter-based extension). Correctly handle messages whose
    length is not a multiple of the block size (padding).
3. CPA game simulation: Implement the IND-CPA game. Run it with a dummy
    adversary that queries the encryption oracle 50 times and then attempts to distinguish
    | conrm their advantage is0.
4. Broken variant (demonstrate the attack): Implement a version that reusesr
    (i.e., deterministic encryption). Show that this version isbrokenby an adversary that
    queries two equal messages and detects the identical ciphertexts.
5. Interface:ExposeEnc(k, m) -> (r, c)andDec(k, r, c) -> mfor use in PA#6.

```
PA #3 | Interactive Demo Deliverable
```
```
Demo: Play the IND-CPA game.The student acts as the adversary:
```
```
 Step 1: Student types two messagesm 0 andm 1 of equal length.
 Step 2: Click \Encrypt." The challenger picks a random bitband showsC=
Enck(mb).
 Step 3: Student guessesb. The app reveals whether the guess was correct and
updates a running advantage counter over multiple rounds (should converge to
0).
 Bonus: a \Reuse nonce" toggle breaks security | with nonce reuse, a correct guess
is trivially forced and the advantage counter jumps to 1.
```
```
Run 20 rounds; conrm advantage 0 :1 in secure mode and = 1:0 in broken mode.
```
### 2.9 PA #4 | Modes of Operation

```
Intuition
Block ciphers operate on xed-size blocks (e.g., 128-bit for AES). Real messages are
longer. Modes of operation specify how to chain block cipher evaluations to handle
arbitrary-length messages securely. Different modes offer different trade-offs in paral-
lelism, error propagation, and security properties.
```
You must support:

Mode 1: CBC (Cipher Block Chaining)

```
IV  Ek C 1  Ek C 2
```
```
M 1 M 2
```
```
Ci=Ek(Ci 1 Mi)
```
Properties: Sequential encryption (cannot parallelize encryption), parallel decryption, one-
block error propagation. Requires random IV.


Mode 2: OFB (Output Feedback)

```
IV Ek  Ek C 1  C 2
```
```
M 1 M 2
```
```
Keystream independent of plaintext
```
Properties:Pre-computable keystream; decryption identical to encryption. Keystream never
reuses state. Bit 
ips in ciphertext produce bit 
ips in plaintext (no error propagation).

Mode 3: Randomized CTR (Counter Mode)

```
r f 0 ; 1 gn Fk(r)  Fk(rC+1) 1  C 2
```
```
M 1 M 2
```
```
r+ 1; r+ 2; : : :
```
Properties: Fully parallelizable (both encryption and decryption), turns block cipher into
stream cipher. The noncermust be unique per key.

```
Comparison Table
```
```
Mode Parallel Enc. Parallel Dec. Random Access Error Prop. IV Reuse
CBC ✓ 2 blocks Fatal
OFB None Fatal
CTR ✓ ✓ ✓ None Fatal
```
```
PA #4 | What You Must Implement
```
1. CBC mode: ImplementCBCEnc(k, IV, M)andCBCDec(k, IV, C)for arbitrary-
    length messages. The IV must be randomly generated per encryption call. Use your
    own PRF/PRP from PA#2 (or your own AES) as the block cipherEk.
2. OFB mode: ImplementOFBEnc(k, IV, M)andOFBDec(k, IV, C). Conrm that
    encryption and decryption are identical operations. Demonstrate that the keystream
    can be pre-computed before the plaintext is known.
3. Randomized CTR mode: ImplementCTREnc(k, M)(samples random noncer
    internally) andCTRDec(k, r, C). Demonstrate parallel block computation.
4. Mode selector interface: Expose a unied API Encrypt(mode, k, M) and
    Decrypt(mode, k, C)wheremode2fCBC,OFB,CTRg. Internally routes to the correct
    implementation.
5. Attack demos: (a) Show CBC IV-reuse attack: encrypt two different messages with
    the same IV and demonstrate that blockileaks ifMi=Mi′. (b) Show OFB keystream-
    reuse attack: encrypt two messages with the same IV and XOR the ciphertexts to
    recover plaintext XOR.


6. Correctness tests: For each mode, verify Dec(k;Enc(k; M)) =Mon at least three
    message lengths: shorter than one block, exactly one block, and spanning multiple
    blocks.

```
PA #4 | Interactive Demo Deliverable
```
```
Demo: Block cipher mode animator.For a 3-block message:
```
```
 Three mode tabs: CBC, OFB, CTR. Switching tabs re-runs the animation.
 Each block is a coloured box. Arrows animate in sequence showing XOR operations
and block cipher calls, with each intermediate value shown in hex.
 \Flip bit" button: student clicks any ciphertext block; the app re-decrypts and
highlights which plaintext blocks are corrupted (CBC: 2 blocks; OFB: only the
same block; CTR: only the same block).
 \Reuse IV" toggle: re-encrypts two messages with the same IV in CBC mode and
highlights the matching ciphertext blocks in red.
```
```
Flip a ciphertext bit in each mode and verify correct error propagation pattern.
```
### 2.10 PA #5 | Message Authentication Codes (MACs)

```
Intuition
The need for integrity: Encryption providescondentiality but notintegrity. An
adversary can 
ip bits in a ciphertext and the decryption will produce a modied (but
valid-looking) plaintext. A MAC allows a receiver to verify that a message was not
tampered with, without requiring a public key.
```
```
MAC Denition
A MAC scheme (Mac;Vrfy) with key spaceK, message spaceM, and tag spaceTsatises:
```
```
 Mack(m)!t: produce tagtfor messagemunder keyk.
 Vrfyk(m; t)!f 0 ; 1 g: verify thattis a valid tag form.
```
```
Security (EUF-CMA):No PPT adversary making polynomially many (mi;Mack(mi))
queries can forge a valid tag on anewmessage.
```
Three constructions to implement:

Construction 1: PRF-MAC (Fixed-length) For messagesm2f 0 ; 1 gn: sett=Fk(m).

Construction 2: CBC-MAC (Variable-length)

```
0 n  Fk  Fk  Fk tagt
```
```
M 1 M 2 M 3
```

Construction 3: HMAC Using a hash functionH: HMACk(m) =H

#### (

(kopad)∥H((k
ipad)∥m)

#### )

```
PA #5 | What You Must Implement
```
1. PRF-MAC (xed-length): ImplementMac(k, m) = Fk(m)andVrfy(k, m, t).
    The PRFFkmust be your own from PA#2. This handles messages of exactly one
    block lengthn.
2. CBC-MAC (variable-length): Extend to arbitrary-length messages using the
    CBC-MAC construction (chainFk over message blocks, output the nal chaining
    value as the tag). Implement bothMacandVrfy.
3. HMAC (forward pointer): PA#5 introduces the HMAC formula for completeness,
    but the full implementation of HMAC belongs inPA#10. In PA#5, you may leave
    a clearly labelled stub functionhmac(k, m)that raisesNotImplementeduntil PA#10
    is complete.Do not use a library HMAC here or in PA#10.
4. MAC)PRF (backward direction): Demonstrate that your PRF-MAC, when
    queried on uniformly random inputs, passes the same PRF distinguishing test from
    PA#2. This concretely witnesses MAC)PRF.
5. EUF-CMA forgery demo: Implement the EUF-CMA game. Show that a naive
    adversary (who has seen up to 50 (mi; ti) pairs) cannot produce a valid tag on a new
    message. Separately, demonstrate alength-extension attack on a naive single-hash
    MAC (t=H(k∥m)) to motivate the HMAC double-hash structure.
6. Interface: ExposeMac(k, m) -> tandVrfy(k, m, t) -> boolfor use in PA#6.

```
PA #5 | Interactive Demo Deliverable
```
```
Demo: MAC forge attempt.The student acts as the EUF-CMA adversary:
```
```
 The app shows a running list of up to 50 signed messages (mi; ti) generated by a
hidden keyk.
 Student types a new messagem(not in the list) and a tagt.
 Click \Submit forgery." The app veries and shows \Forgery accepted" or \Forgery
rejected."
 A counter tracks forgery attempts and successes. Graders expect 0 successes in
20 attempts.
 Separate tab: \Length-extension demo" | student types a suffixm′, app shows
the extended tag onm∥pad∥m′being computed fromtalone (withoutk), demon-
strating the naiveH(k∥m) vulnerability.
```
### 2.11 PA #6 | CCA-Secure Symmetric Encryption.

```
Intuition
Why CPA is not enough:CPA-secure schemes aremalleable|an adversary can mod-
ify a ciphertext in a predictable way to alter the plaintext without knowing the key. CCA
(Chosen-Ciphertext Attack) security eliminates this by requiring that even an adversary
with a decryption oracle cannot break security. TheEncrypt-then-MACparadigm
achieves this.
```

Encrypt-then-MAC Construction

Keys:Independent encryption keykEand MAC keykM.
Encryptionofm:

1. CE EnckE(m) (CPA-secure, e.g., PA#3)
2. t MackM(CE) (EUF-CMA secure, e.g., PA#5)
3. Output (CE; t)

Decryptionof (CE; t):

1. If VrfykM(CE; t) = 0: output?(reject tampered ciphertext)
2. Else: output DeckE(CE)

```
m CE= EnckE(m) t= MackM(CE)
```
```
Verifytbefore decrypt! Output: (CE; t)
MAC check prevents CCA oracle exploitation
```
Security Claim

If Enc is CPA-secure and Mac is EUF-CMA secure, then Encrypt-then-MAC isCCA2-
secure. The MAC verication step means any adversary query to the decryption oracle
on a modied ciphertext is rejected, nullifying the adaptive oracle.

PA #6 | What You Must Implement

1. Encrypt-then-MAC: Implement CCAEnc(kE, kM, m) andCCADec(kE, kM, c,
    t). Internally,CCAEnccalls your PA#3Encand your PA#5Mac. CCADecmust
    callVrfybeforecallingDec| rejecting with?on MAC failure.
2. Key separation: Use independently sampled keyskEandkM (never the same key
    for both). Demonstrate that reusing a single key for both roles creates exploitable
    correlations.
3. CCA2 game simulation: Implement the IND-CCA2 game. Your adversary gets
    both an encryption oracle and a decryption oracle (which rejects the challenge cipher-
    text). Show that your scheme's adversary advantage is0.
4. Malleability attack on CPA-only: Show that your PA#3 CPA-secure scheme
    (without the MAC) ismalleable: givenC=⟨r; Fk(r)m⟩, an adversary can 
ip biti
    of the ciphertext to produce a ciphertext formwith biti
ipped, without knowingk
    orm. Contrast this with your CCA-secure scheme where the same attack is detected
    and rejected.
5. Interface: Expose CCAEnc(kE, kM, m) -> (c, t) andCCADec(kE, kM, c, t)
    -> m or?.

PA #6 | Interactive Demo Deliverable

Demo: Malleability attack panel.

```
 Left side (CPA-only): student is shown a ciphertextC=⟨r; Fk(r)m⟩. A bit-
ip
```

```
tool lets them click any bit. The app decrypts the modied ciphertext and shows
the corrupted plaintext | demonstrating malleability.
 Right side (CCA / Encrypt-then-MAC): the same bit-
ip attempt is shown, but
the MAC verication step res and returns?. The plaintext never decrypts.
 Both sides update live as the student 
ips different bits.
```
Flip a bit on the left; conrm modied plaintext appears. Flip the same bit on the right;
conrm?is returned.


## 3 Part II: Hashing and Data Integrity

### Standalone Concept: The Birthday Bound (Theory)

```
Standalone Concept: Birthday Bound | Security Floor of Every Hash Func-
tion
The Birthday Bound is astandalone, information-theoretic result: it applies toany
hash function regardless of how it is constructed, and it denes a hard security ceiling
that no engineering can overcome.
The Birthday Problem: In a group ofkpeople, the probability that two share a
birthday exceeds 50% whenk
```
```
p
365 23. The intuition is that we are countingpairs,
not individuals:kpeople form
```
```
(k
2
```
#### )

```
k^2 =2 pairs.
Cryptographic consequence:For a hash functionH:f 0 ; 1 g!f 0 ; 1 gn:
```
```
 By the pigeonhole principle, collisionsmustexist (domain>range).
 Finding a collision requires onlyO(2n=^2 ) random hash evaluations in expectation.
 This is theabsolute lower bound on hash function strength: no hash with
n-bit output can require more thanO(2n=^2 ) work to collide.
```
```
Practical impact:MD5 (n= 128):  264 ops to nd collision (broken 2005). SHA-1
(n= 160): 280 ops (broken 2017). SHA-256 (n= 256): 2128 ops (currently secure).
This is why modern hashes use at least 256-bit output.
PA#9 implements this attack concretely| see Section3.3. You will run the
algorithm on your own hash functions and empirically conrm theO(2n=^2 ) prediction.
```
(^00) : 2
p
N 0 : 4
p
N 0 : 6
p
N 0 : 8
p
N
p
N

#### 0

#### 0 : 25

#### 0 : 5

#### 0 : 75

#### 1

```
kpN
```
```
Number of messages hashed (k)
```
```
Collision probability
```
```
Birthday Collision Probability vs. Samples
```
### 3.1 PA #7 | Merkle-Damgard Transform

```
Intuition
We want hash functions that accept inputs ofanylength but produce xed-length out-
puts. The Merkle-Damgrd transform is thedomain extensiontechnique: given a xed-
length compression functionh:f 0 ; 1 gn+b! f 0 ; 1 gn, it constructs a collision-resistant
hash for arbitrary-length inputs.Key theorem:Any collision in the output of the MD
```

transform implies a collision inh.

Merkle-Damgrd Transform

Input:MessageMof any length; xed IV = 0n
Preprocessing:PadMto a multiple ofbbits usingMD-strengtheningpadding:
M∥ 1 ∥ 0 ∥⟨jMj⟩(append 1-bit, then zeros, then 64-bit length eld)
Algorithm:

1. Parse padded message as blocksM 1 ; M 2 ; : : : ; Mℓ2f 0 ; 1 gb
2. z 0 IV
3. Fori= 1 toℓ:zi h(zi 1 ∥Mi)
4. Outputzℓ

```
IV = 0n h h h H(M)
```
```
M 1 M 2 M 3 ∥pad
```
```
z 0 z 1 z 2 z 3
```
```
arbitrary-length messageM
```
Security Claim

Ifhis a collision-resistant compression function, then the MD transformHis collision-
resistant. Proof sketch: If adversary ndsM̸=M′withH(M) =H(M′), trace back
through the chain to nd a collision inh(possible becauseh's inputs differ whenever the
chaining values differ).

PA #7 | What You Must Implement

1. Merkle-Damgrd framework: Implement a generic MerkleDamgard(compress,
    IV, blocksize) class/function that accepts any compression function h :
    f 0 ; 1 gn+b!f 0 ; 1 gnas a parameter and produces a hash function for arbitrary-length
    inputs.
2. MD-strengthening padding: Implement the padding correctly: append a 1-bit,
    then enough 0-bits, then a 64-bit big-endian encoding of the original message length,
    so the padded message is a multiple ofbbits.
3. Dummy compression plug-in: For testing PA#7 in isolation, supply a toy com-
    pression function (e.g., XOR-based) to verify the MD framework produces correct-
    length outputs and handles boundary cases (empty message, exactly-one-block mes-
    sage, multi-block message).
4. Collision propagation demo: Show the reduction: given two inputs that collide
    under your toy compression function, demonstrate that they also collide under the full
    MD hash. This concretely illustrates why security ofHreduces to security ofh.
5. Interface: Exposehash(message, compressionfn) -> digestso that PA#8 can
    plug in the DLP compression function directly.


```
PA #7 | Interactive Demo Deliverable
```
```
Demo: Merkle-Damgard chain viewer.
```
```
 Student types an arbitrary message (text or hex).
 The app splits it into blocks, applies MD-strengthening padding, and displays each
block as a labelled box.
 An animated chain showsz 0 !h(z 0 ; M 1 )!h(z 1 ; M 2 )! with each chaining
value shown in hex.
 Editing any block re-computes the chain from that block onwards (showing
avalanche effect).
```
```
Toy parameters: Use your XOR-based toy compression function from PA#7's test
suite for speed. Block size 8 bytes, output 4 bytes.
```
### 3.2 PA #8 | DLP-Based Collision-Resistant Hash Function.

```
Intuition
The Merkle-Damgrd transform providesstructurebut not security|security comes from
the compression function. Here we instantiatehusing theDiscrete Logarithm Prob-
lem, giving a provably collision-resistant compression function under the DL assumption.
This is a purely number-theoretic construction with a clean security proof.
```
Setup

LetG=⟨g⟩be a cyclic group of prime orderqwhere DLP is hard (e.g., a safe-prime subgroup
ofZp, or an elliptic curve group). Letg; h 2 Gwithh=g^ for unknown (i.e., logghis
unknown).

DLP Compression Function

```
DLP-based Compression Function
```
```
Dene Compress :ZqZq!G:
```
```
h(x; y) =gxhy=gx+y (modp)
```
```
Equivalently written ash(x; y) =gx+yif we seth=g(simplest case):
```
```
h(x; y) =gx+ymodp
```
Collision Resistance Proof Sketch:Suppose adversary nds (x; y)̸= (x′; y′) withh(x; y) =
h(x′; y′), i.e.:
gx^hy=gx
′
^hy
′
(modp)

Thengxx
′
= ^hy
′y
, so logg^h = xx
′
y′y (modq). This would solve DLP, contradicting our
assumption!


Full Pipeline

```
MessageM(arbitrary length)
```
```
Merkle-Damgrd (PA#7)
```
```
h(x; y) =gx+y(DLP compression)
```
```
Hash digest 2 G
```
```
block-by-block Security: CRHF under DLP
```
```
PA #8 | What You Must Implement
```
1. Group setup: Select and implement a prime-order group where DLP is hard. Ac-
    ceptable choices: (a) a safe-prime subgroup ofZpwithp= 2q+ 1,qprime, group
    orderq; (b) an elliptic curve group (e.g., Curve25519 parameters | but implement
    the arithmetic yourself, no library). Generategand^h=g^ for a randomly chosen
    that is thendiscarded(nobody should know ).
2. DLP compression function: Implement h(x; y) =gx^hymodp (or the elliptic
    curve analogue) as a function mapping twoZqinputs to one group element. This is
    your compression function for PA#7.
3. Full CRHF: Plug your DLP compression function into the PA#7 Merkle-Damgrd
    framework to produce a complete collision-resistant hash functionDLPHash(message)
    -> groupelement.
4. Collision resistance demo: Show that you cannot nd a collision without solving
    DLP. Specically: (a) demonstrate that random pairs (x; y)̸= (x′; y′) withh(x; y) =
    h(x′; y′) would require computing logg^h; (b) write a brute-force collision nder for a
    tiny parameter (q  216 ) and show it requires enumeratingO(2^8 ) =O(pq) values
    (birthday bound).
5. Integration test: Hash at least ve messages of different lengths throughDLPHash
    and conrm distinct inputs produce distinct digests.
6. Forward pointer to PA#10: YourDLPHashis the hash function that PA#10 will
    wrap in HMAC. Ensure the interface matches: DLPHash(message) -> byteswith
    congurable output length.

```
PA #8 | Interactive Demo Deliverable
```
```
Demo: DLP hash live.
 Student types a message; the app computesDLPHash(message)and displays the
group element as a hex string.
 A \Collision hunt" button runs the birthday attack (toyn= 16-bit output) in
the background, updating a counter of hashes evaluated, and highlights the two
colliding inputs when found.
 A progress bar shows how close the count is to 2n=^2 = 256.
Toy parameters:q 216 , truncated to 16-bit output for the collision demo. Full-size
hash shown separately.
```

### 3.3 PA #9 | Birthday Attack (Collision Finding)

```
Intuition
Theory meets implementation: The Birthday Attack is not merely a theoretical
bound|it is anexecutable algorithm. PA#9 asks you to implement it, run it on your
own hash functions with small parameters, and empirically conrm theO(2n=^2 ) be-
haviour. This grounds the abstract security analysis in concrete experimental evidence,
and demonstrates that your CRHF from PA#8 isexactly as hardas the birthday bound
predicts|no better, no worse.
```
The Algorithm in Detail

Two standard approaches:

Approach 1: Naive birthday (sort-based) Hashk=⌈ 1 : 2  2 n=^2 ⌉random inputs, sort by
output, scan for duplicates. TimeO(klogk), spaceO(k).

Approach 2: Floyd's cycle detection (space-efficient) Treat the hash as a function
f :f 0 ; 1 gn! f 0 ; 1 gn(setf(x) =H(x) truncated tonbits). Use tortoise-and-hare to nd a
cycle, then extract a collision. TimeO(2n=^2 ), spaceO(1).

```
randomxi H H(xi) Sort / hashtable
Collision!
H(xi) =H(xj)
```
```
repeatO(2n=^2 ) times
total work:O(2n=^2 ) hash evaluations
```
```
Security Claim
```
```
For any hash withn-bit output: (a) no algorithm can nd a collision in fewer than
Ω(2n=^2 ) queries (lower bound); (b) the birthday algorithm nds one inO(2n=^2 ) queries
(upper bound). The bound is thereforetight. Increasing output length by 1 bit doubles
the cost of nding a collision.
```
```
PA #9 | What You Must Implement
```
1. Naive birthday algorithm: Implement birthdayattack(hashfn, n,
    numtrials) that hashes random inputs, stores outputs in a dictionary, and
    returns the rst collision pair (x; x′) withx̸=x′andH(x) =H(x′). nis the output
    bit length;hashfnis any callable.
2. Floyd's cycle-nding attack: Implement the space-efficient variant using tortoise-
    and-hare onf(x) =H(x) (treating then-bit output as the next input). Return the
    collision pair without storing all intermediate hashes.
3. Attack your own toy hash: Design a deliberately weak hash function withn=
    8 ; 12 ;16 output bits. Run both algorithms on it. Plot the number of evaluations
    needed against 2n=^2 for eachnvalue and conrm the empirical count matches the
    theoretical prediction.


4. Attack truncated DLP hash: Take your PA#8 DLP hash and truncate its output
    ton= 16 bits. Run the birthday attack. Report: (a) how many evaluations were
    needed; (b) the ratio evaluations= 2 n=^2 ; (c) the two colliding inputs. This concretely
    shows that even a provably-secure hash is broken at the birthday bound if its output
    is too short.
5. Empirical birthday curve: Run 100 independent trials for each of n 2
    f 8 ; 10 ; 12 ; 14 ; 16 gbits. For eachn, plot the distribution of the number of queries until
    rst collision. Overlay the theoretical curve 1ek(k1)=^2
       n+1
         . Conrm the match.
6. MD5/SHA-1 context: Compute 2n=^2 for n= 128 (MD5) andn= 160 (SHA-
    1). Express the result in terms of modern CPU speed (e.g., if a CPU hashes 10^9
    values/sec, how many seconds/years does the attack take?). This contextualises why
    MD5 is broken and SHA-1 is deprecated.

PA #9 | Interactive Demo Deliverable

Demo: Live birthday attack.

```
 A slider lets the student pick output bit-lengthn2f 8 ; 10 ; 12 ; 14 ; 16 g.
 Click \Run attack." A counter increments live as hashes are computed. When a
collision is found, the two inputs and their shared hash are displayed.
 A live chart plots \hashes computed" vs \collision probability" and overlays the
theoretical curve 1ek
```
(^2) = 2 n
 The expected collision point 2n=^2 is shown as a vertical marker; the student sees
the empirical collision landing near it.
Run forn= 12; conrm collision found near 2^6 = 64 evaluations on average.

### 3.4 PA #10 | HMAC and HMAC-Based CCA-Secure Encryption

Intuition

The HMAC bridge:PA#10 is the assignment where the two worlds of the course|
symmetric cryptography (Part I) and hashing (Part II)|meet. HMAC takes your hash
function (PA#8) and produces a MAC (a Part I primitive). The security proof of HMAC
uses the PRF security of the compression function, not collision resistance. This is what
earns HMAC its place in the Minicrypt clique: it is the concrete witness of the CRHF
$MAC equivalence.
Then, armed with a hash-based MAC, we rebuild CCA-secure encryption using Encrypt-
then-HMAC, closing the loop back to PA#6 but now with a hash-derived authentication
tag instead of a PRF-derived one.


HMAC Construction

```
HMAC Denition
LetH : f 0 ; 1 g! f 0 ; 1 gn be a hash function with block size bbytes. For key k
(padded/hashed tobbytes) and messagem:
```
```
HMACk(m) =H
```
#### (

```
(kopad)
| {z }
outer key
```
```
∥H((kipad)
| {z }
inner key
```
```
∥m)
```
#### )

```
whereipad=0x36bandopad=0x5Cbare xed constants.
```
```
keyk
```
```
kipad kopad
```
```
messagem H(inner) inner hashH(outer) HMAC tag
```
```
H(kipad∥m)
```
Why Two Hashes? The Length-Extension Attack

A naive MAC t= H(k∥m) is broken by alength-extension attack: given H(k∥m), an
adversary can compute H(k∥m∥pad∥m′) for any suffix m′ without knowingk, because the
Merkle-Damgrd state after processingk∥mis exactlyH(k∥m).

HMAC defeats this by using the inner hash output as a xed-length input to afresh outer
hash invocation keyed withkopad. The adversary cannot continue the inner hash without
restarting from the keyed IV.

```
H(k∥m) (broken) H(k∥m∥pad∥m′)
```
```
length-extend!
```
```
adversary can do this withoutk
```
```
HMACk(m) HMACk(m∥m′)?
```
```
impossible withoutk
```
```
outerHwith fresh key blocks extension
```
HMAC-Based CCA-Secure Encryption

Once HMAC is implemented, we rebuild the Encrypt-then-MAC paradigm from PA#6, this
time using HMAC as the authentication layer. This is the practical standard (TLS 1.2 uses
exactly this pattern):

```
C= EnckE(m); t= HMACkM(C); send (C; t)
```
```
Verify: HMACkM(C)=? tbefore decrypting
```

Security Claim

HMAC is EUF-CMA secure if the compression functionhofHis a PRF. This is weaker
than requiring collision resistance ofH itself | HMAC remains secure even against
adversaries who can nd collisions inH(as happened to MD5), as long ashretains PRF
security. This is why HMAC-MD5 was used safely in TLS long after MD5 collisions were
found.

PA #10 | What You Must Implement

1. HMAC over your PA#8 hash: ImplementHMAC(k, m)using your ownDLPHash
    from PA#8 as the underlyingH. Implement key padding (ifjkj> b, hash it rst;
    ifjkj< b, zero-pad tobbytes). ImplementHMACVerify(k, m, t) -> boolusing a
    constant-time comparison to prevent timing attacks.
2. CRHF) MAC (forward, bidirectional): Demonstrate that your HMAC is a
    secure MAC by running the EUF-CMA game: after 50 queries to the HMAC oracle,
    conrm the adversary cannot forge a tag on a new message.
3. MAC)CRHF (backward, bidirectional): Demonstrate the reverse direction.
    Construct a new compression functionh′(cv; block) = HMACk(cv∥block) for a xed
    public keyk. Plugh′into your PA#7 Merkle-Damgrd framework to produce a new
    hash functionMACHash. Show that nding a collision in MACHashwould require
    forging an HMAC tag.
4. Length-extension attack demo: Show concretely that the naive MACt=H(k∥m)
    (using your PA#8 hash directly,withoutthe HMAC structure) is broken by a length-
    extension attack: given (m; t), construct a valid (m∥pad∥m′; t′) for any chosenm′.
    Then show the same attack fails onHMAC.
5. Encrypt-then-HMAC (CCA-secure encryption): ImplementEtHEnc(kE, kM,
    m)using your PA#3 CPA-secure encryption and your new HMAC: encrypt rst, then
    HMAC the ciphertext. ImplementEtHDec(kE, kM, c, t): verify HMAC before
    decrypting; return?on failure.
6. CCA2 game for Encrypt-then-HMAC: Run the IND-CCA2 game. Conrm the
    scheme correctly rejects modied ciphertexts and achieves negligible adversary advan-
    tage. Compare performance (tag size, computation cost) against the PRF-MAC-based
    scheme from PA#6.
7. Constant-time comparison: Implementsecurecompare(t1, t2)that compares
    two tags in constant time (XOR all bytes, check result is zero). Demonstrate that
    a naive early-exit comparison leaks the tag via a timing side channel (measure time
    difference for tags differing in early vs. late bytes).
8. Interface: Expose HMAC(k, m) -> tag, HMACVerify(k, m, t) -> bool,
    EtHEnc(kE, kM, m) -> (c, t), andEtHDec(kE, kM, c, t) -> m or ?.

PA #10 | Interactive Demo Deliverable

Demo: Length-extension vs HMAC side-by-side.

```
 Left panel (brokenH(k∥m)): student is shown (m; t). They type a suffixm′. The
app computes a valid tag form∥pad∥m′ without knowingkand shows \Forgery
succeeded."
 Right panel (HMAC): same attempt. The app shows \Forgery failed" | computing
HMACk(m∥pad∥m′) requiresk.
 A toggle switches the underlying hash between your PA#8 DLP hash and a place-
```

```
holder SHA-256 (for comparison), showing HMAC works with both.
```
Conrm length-extension succeeds on the left and fails on the right for any typed suffix.


## 4 Part III: Public-Key Cryptography (Cryptomania)

```
Intuition
The Key Distribution Problem:Symmetric cryptography requires Alice and Bob to
share a secret keybeforecommunicating. How do they do this over an insecure channel?
Public-key cryptography (PKC), powered bytrapdoor one-way functions, solves this:
everyone can encrypt using a public key, but only the holder of the private key (trapdoor)
can decrypt. This jumps us from Minicrypt toCryptomania.
```
```
Alice (pk,sk) Bob (has pk)
```
```
Eve (sees pk,C)
```
```
pk(public)
```
```
C= Encpk(m)
```
```
Eve can't decrypt!
```
### 4.1 PA #11 | Diffie-Hellman Key Exchange (SKE)

```
Intuition
Two parties, Alice and Bob, wish to establish a shared secret over a completely public
(eavesdropped) channel, without any prior shared secret. The DH protocol achieves this
using the hardness of theComputational Diffie-Hellman (CDH)problem: givenga
andgb, computegab.
```
```
Diffie-Hellman Protocol
Public parameters:Primep, generatorgofZp(orderq).
```
1. Alice samplesa Zq, sendsA=gamodp.
2. Bob samplesb Zq, sendsB=gbmodp.
3. Alice computesK=Ba=gab. Bob computesK=Ab=gab.

```
Both now shareK=gab, which Eve cannot compute (CDH assumption).
```
```
Alice:a Zq Bob:b Zq
```
```
gamodp
gbmodp
```
```
ComputesK= (gb)a=gab ComputesK= (ga)b=gab
```
```
Shared secretK=gab
```
Security note:Basic DH isnotauthenticated|it is vulnerable to Man-in-the-Middle (MITM)
attacks. Authentication requires digital signatures (PA#15).


```
PA #11 | What You Must Implement
```
1. Group parameter generation: Generate a safe primep= 2q+1 (using your PA#13
    Miller-Rabin tester) and a generatorgof the prime-order subgroup ofZpof orderq.
2. DH key exchange protocol: Implement both parties (Alice and Bob) as
    functions: dhalicestep1() -> (a, A) produces a private exponent and pub-
    lic value; dhbobstep1() -> (b, B) likewise; dhalicestep2(a, B) -> K and
    dhbobstep2(b, A) -> Kcompute the shared secret. VerifyKA=KB.
3. MITM attack demo: Implement an active adversary Eve who interceptsAand
    B, substitutes her own valuesA′=geandB′=ge, and establishes separate shared
    secrets with Alice and Bob. Show she can read all traffic.
4. CDH hardness: For small parameters (q 220 ), demonstrate that computinggab
    fromgaandgbwithout knowingaorbrequires a brute-force search. Report the time
    taken.

```
PA #11 | Interactive Demo Deliverable
```
```
Demo: Live Diffie-Hellman exchange.
```
```
 Two panels: Alice (left) and Bob (right). Each has an input for their private
exponentaorb(or a \randomise" button).
 Click \Exchange." The app animates: Alice sendsgato Bob, Bob sendsgbto Alice.
 Both panels compute and display the shared secretK=gab, shown in green when
they match.
 \Enable Eve" checkbox inserts a MITM: Eve intercepts, substitutes her own values,
and both shared secrets change. Eve's panel shows she now holds both secrets.
```
```
Toy parameters:p 232 safe prime for instant computation. Values shown in hex.
```
### 4.2 PA #12 | Textbook RSA.

```
Standalone Concept: Prime Factoring Assumption
```
```
The security of RSA rests on: givenN=pqfor large primesp; q, it is computationally
infeasible to recoverp andq. (Best known algorithm: Number Field Sieve, runs in
eO((lnN)
```
1 = (^3) (ln lnN) 2 = (^3) )
time.)
RSA Key Generation and Cryptosystem
Key Generation:

1. Choose large primesp; q(use PA#13!); setN=pq.
2. Computeφ(N) = (p1)(q1).
3. Chooseewith gcd(e; φ(N)) = 1 (commonlye= 65537).
4. Computed=e^1 modφ(N) via extended Euclidean algorithm.
5. Public key: (N; e). Private key: (N; d).

```
Encryption:C=MemodN
Decryption:M=CdmodN(sinceCd=Med=M1+kφ(N)=Mby Euler's theorem)
```

```
Warning: Textbook RSA is NOT Secure!
```
```
Textbook RSA isdeterministic|encrypting the same plaintext always yields the same
ciphertext. This immediately breaks CPA security. Never use raw RSA in practice;
always apply padding. This assignment therefore requirestwoimplementations: text-
book RSA (to understand the raw structure) and PKCS#1 v1.5 padded RSA (to achieve
practical security).
```
Required Extension: PKCS#1 v1.5 Padding

PKCS#1 v1.5 (RFC 2313) is the historically standard padding scheme that turns textbook
RSA into a usable encryption primitive by injecting randomness and structure into the message
before encryption.

```
PKCS#1 v1.5 Encryption Padding
```
```
Input:Messagemof lengthjmjbytes; RSA modulusNofkbytes.
Requirejmjk11.
Padded plaintextEM:
```
```
EM= 00|{z}
leading zero
```
```
∥|{z} 02
type
```
```
∥ |{z}P S
random nonzero bytes, 8
```
```
∥ |{z} 00
separator
```
```
∥ |{z}m
message
```
```
 The0x00 02header signals encryption padding (vs.0x00 01for signatures).
 P Sis at least 8 bytes ofcryptographically random, nonzerobytes.
 Total length ofEM equalsk(the modulus byte length).
```
```
Encrypt:C=EMemodN Decrypt:EM=CdmodN, then strip padding.
```
```
00 02 P S(random,8 bytes) 00 messagem
```
```
kbytes (= modulus size)
```
```
Bleichenbacher's Attack: Why Even PKCS#1 v1.5 Is Fragile
```
```
In 1998, Daniel Bleichenbacher showed that apadding oracle|a service that reveals
whether a ciphertext decrypts to a valid PKCS#1 v1.5 format|can be exploited to
decrypt any RSA ciphertext with 220 adaptive queries. This is an adaptive CCA2
attack.
Lesson: PKCS#1 v1.5 is CPA-secure butnot CCA-secure. The modern replacement
isOAEP(Optimal Asymmetric Encryption Padding), which achieves CCA2-security in
the random oracle model. PA#17 addresses full CCA-secure PKC using the Sign-then-
Encrypt paradigm.
```
```
PA #12 | What You Must Implement
```
1. Key generation: Implement rsakeygen(bits)using your PA#13 Miller-Rabin
    tester to generate two⌊bits= 2 ⌋-bit primesp; q. ComputeN=pq,φ(N) = (p1)(q1),
    choosee= 65537, computed=e^1 modφ(N) using the extended Euclidean algorithm
    (implement this yourself).


2. Textbook RSA: Implementrsaenc(pk, m) = m^e mod Nandrsadec(sk, c) =
    c^d mod N. Use fast modular exponentiation (square-and-multiply | implement this
    yourself, no librarypow).
3. PKCS#1 v1.5: Implementpkcs15enc(pk, m)(padmas 00∥ 02 ∥P S∥ 00 ∥mthen
    apply textbook RSA) andpkcs15dec(sk, c)(apply textbook RSA then strip and
    validate padding, returning?on malformed padding).
4. Determinism attack on textbook RSA: Show that encrypting the same short
    message (e.g., a vote or a coin 
ip) twice produces identical ciphertexts, leaking infor-
    mation. Contrast with PKCS#1 v1.5 where randomP Sprevents this.
5. Bleichenbacher padding oracle (simplied): Implement a toy version with small
    N(512 bits): given a ciphertext and a padding-validation oracle, recover the plain-
    text using the adaptive chosen-ciphertext attack. This demonstrates why PKCS#1
    v1.5 is not CCA-secure.
6. Interface: ExposeEnc(pk, m) -> candDec(sk, c) -> min both textbook and
    PKCS#1 v1.5 variants, for use in PA#14, PA#15, and PA#18. Your key generation
    must also output (p; q; dp; dq; qinv) for use in PA#14's CRT-based decryption.

```
PA #12 | Interactive Demo Deliverable
```
```
Demo: Textbook RSA determinism attack.
```
```
 Student types a short message (e.g., \yes" or \no", simulating a vote).
 Click \Encrypt twice." Both ciphertexts are shown | they are identical. A red
banner reads \Identical ciphertexts: plaintext leaked."
 Switch to PKCS#1 v1.5 mode: click \Encrypt twice" again. Ciphertexts differ
each time. Green banner.
 A \Padding bytes" panel shows the randomP Sbytes that differ between the two
encryptions.
```
```
Toy parameters: 512-bitN for fast in-browser computation. Graders do not need
2048-bit keys for this demo.
```
### 4.3 PA #13 | Miller-Rabin Primality Testing.

```
Standalone Concept: Primality Testing
```
```
RSA and ElGamal both require large primes ( 1024 bits). Deterministic primality
testing (AKS) is polynomial but slow. Miller-Rabin is a fastprobabilistictest: if
it says \composite," it is denitely correct; if it says \prime," there is at most a 4k
probability of error afterkrounds.
```
```
Miller-Rabin Algorithm
```
```
Input:Odd integern >2; number of roundsk.
```
1. Writen1 = 2sdwithdodd.
2. Fori= 1 tok:
    (a) Choosea f 2 ; : : : ; n 2 gat random.


```
(b)Computex admodn.
(c) Ifx= 1 orx=n1: continue.
(d)Forr= 1 tos1:
 x x^2 modn
 Ifx=n1: break (go to next round)
(e) Ifx̸=n1: returnComposite.
```
3. ReturnProbably Prime.

Error probability: 4 kforkrounds. Fork= 40, probability 10 ^24.

PA #13 | What You Must Implement

1. Miller-Rabin test: Implementmillerrabin(n, k)exactly as described above. Use
    your own modular exponentiation (square-and-multiply). ReturnPROBABLYPRIMEor
    COMPOSITE.
2. Prime generation: Implementgenprime(bits)that repeatedly samples a random
    oddb-bit integer and tests it withk= 40 rounds until a probable prime is found.
    Verify the output passes 100 rounds of testing as a sanity check.
3. Carmichael number demo: Show thatn= 561 (the smallest Carmichael number)
    passes a nave Fermat primality test but is correctly rejected by Miller-Rabin.
4. Performance benchmark: Report the average number of candidates sampled before
    nding a 512-bit prime, a 1024-bit prime, and a 2048-bit prime. Compare to the
    theoreticalO(lnn) candidates predicted by the Prime Number Theorem.
5. Interface: Exposeisprime(n) -> boolandgenprime(bits) -> intfor use in
    PA#11 and PA#12.

PA #13 | Interactive Demo Deliverable

Demo: Primality tester.

```
 A number input eld (student types any integer up to 20 digits).
 A \rounds" slider (k= 1{40).
 Click \Test." The app runs Miller-Rabin and shows: PRIME or COMPOSITE,
time taken, and the list of witnessesaitested with their computed values at each
round.
 Pre-loaded examples: 561 (Carmichael, fooled by Fermat but caught by Miller-
Rabin), a known 512-bit prime, and a known composite. Student can click these
for instant demo.
```
Enter 561 | must return COMPOSITE after 1+ rounds despite passing Fermat.


### 4.4 PA #14 | Chinese Remainder Theorem & Breaking Textbook RSA

```
Intuition
Two roles of CRT in RSA:The Chinese Remainder Theorem plays two opposite roles
in RSA. First, it is atool for the honest party|RSA decryption can be made roughly
four times faster by working modulopandqseparately (CRT-based RSA). Second, it is
aweapon for the adversary|if the same messagemis broadcast to multiple recipients
using a small public exponente, CRT lets an attacker recovermentirely without knowing
any private key. PA#14 implements both.
```
The Chinese Remainder Theorem

```
Chinese Remainder Theorem (CRT)
```
```
Letn 1 ; n 2 ; : : : ; nkbe pairwise coprime moduli (i.e., gcd(ni; nj) = 1 fori̸=j). For any
integersa 1 ; a 2 ; : : : ; ak, the system of congruences
```
```
xa 1 (modn 1 ); xa 2 (modn 2 ); : : : ; xak (modnk)
```
```
has auniquesolution moduloN=n 1 n 2 nk:
```
```
x=
```
```
∑k
```
```
i=1
```
```
aiMi(Mi^1 modni) (modN) whereMi=N=ni
```
```
xmodN
```
```
xmodn 1 =a 1 xmodn 2 =a 2 xmodn 3 =a 3
```
```
CRT reconstruct
```
```
Givena 1 ; a 2 ; a 3 andn 1 ; n 2 ; n 3 coprime)uniquexmodN
```
Application 1: CRT-Based RSA Decryption (Garner's Algorithm)

Standard RSA decryption computesCdmodNwhereN 22048 | a single expensive modular
exponentiation. Since the private key holder knowspandq, they can instead compute:

```
mp=Cdpmodp; mq=Cdqmodq; then combine via CRT
```
wheredp=dmod (p1) anddq=dmod (q1). The exponents are half the size, and the
moduli are half the size | giving a 4 speedup.

```
Garner's CRT Recombination
```
```
Givenmp=Cdpmodpandmq=Cdqmodq:
```
1. Leth=qinv(mpmq) modp, whereqinv=q^1 modp.
2. Outputm=mq+hq.
This is equivalent toCdmodNbut uses exponentiations modulopandqindividually.


Application 2: Hastad's Broadcast Attack (CRT Breaks Textbook RSA)

```
Hastad's Broadcast Attack
Setup:A sender broadcasts the same messagemtoedifferent recipients, each with their
own RSA modulusNibut all using the same small public exponente(e.g.,e= 3). The
adversary sees:
```
```
c 1 =memodN 1 ; c 2 =memodN 2 ; : : : ; ce=memodNe
```
```
Attack: Sincem < Nifor alli, we haveme< N 1 N 2 Ne. Apply CRT to recover
memod (N 1 N 2 Ne), which equals me exactly (as an integer). Then take thee-th
integer root to getm.
Fore= 3:Three ciphertexts suffice. CRT givesx=m^3 as an integer; compute⌊x^1 =^3 ⌋.
This requires no factoring and no private keys.It defeats textbook RSA completely
wheneis small andmis short.
```
```
plaintextm
```
```
c 1 =m^3 modN 1
recipient 1
```
```
c 2 =m^3 modN 2
recipient 2
```
```
c 3 =m^3 modN 3
recipient 3
```
```
CRT)m^3 modN 1 N 2 N 3
```
```
⌊(m^3 )^1 =^3 ⌋=m ✓
```
```
integer cube root
```
```
adversary
```
Why This Attack Fails on Padded RSA

With PKCS#1 v1.5 or OAEP, the message padded before encryption includes random bytes,
so each recipient encrypts adifferentpadded value. The three ciphertexts no longer share a
commonm, so CRT recovers garbage, and the integer cube root step fails.

```
PA #14 | What You Must Implement
```
1. CRT solver: Implementcrt(residues, moduli) -> xthat takes a list of (ai; ni)
    pairs (with pairwise coprimeni) and returns the unique xmod

#### ∏

```
nisatisfying all
congruences. Use the constructive formula with modular inverses. Implement
modinverse(a, n)yourself via the extended Euclidean algorithm (no library).
```
2. CRT-based RSA decryption (Garner's algorithm): Implement
    rsadeccrt(sk, c)whereskincludes (p; q; dp; dq; qinv). Computemp=cdpmodp,
    mq = cdqmodq, then recombine using Garner's formula. Verify correctness:
    rsadeccrt(sk, c) == rsadec(sk, c)for 100 random messages.
3. Performance comparison: Benchmarkrsadec(standard) vs.rsadeccrt(Gar-
    ner) for 1000 decryptions each at 1024-bit and 2048-bit key sizes. Report the speedup
    ratio and conrm it is3{4.
4. Hastad's broadcast attack: Implement hastadattack(ciphertexts, moduli,
    e)whereciphertexts[i] = m^e mod moduli[i]fori= 0; : : : ; e1. Steps:


```
(a) Apply your CRT solver to recoverx=memod
```
#### ∏

```
Ni.
(b)Compute the integere-th root of x(implement Newton's method for integer
roots).
(c) Returnm.
Test withe= 3: generate three independent RSA key pairs (N 1 ;3);(N 2 ;3);(N 3 ;3),
encrypt the same short messagemto all three, and recovermusing your attack.
Conrmmis recovered exactly.
```
5. Attack boundary: Determine the maximum message length (in bytes) for which
    Hastad's attack withe = 3 succeeds, given three 1024-bit moduli. Explain why
    messages withm^3 N 1 N 2 N 3 are safe from this specic attack (though still insecure
    for other reasons).
6. Padding defeats the attack: Show that if each sender applies PKCS#1 v1.5
    padding (from PA#12) before encrypting, the broadcast attack fails | the three
    padded plaintexts differ, so CRT does not recoverm^3 and the integer root step re-
    turns garbage.
7. Interface: Exposecrt(residues, moduli) -> int,rsadeccrt(sk, c) -> int,
    andhastadattack(ciphertexts, moduli, e) -> intfor use in PA#17 (which ex-
    ploits this to motivate CCA-secure PKC).

```
PA #14 | Interactive Demo Deliverable
```
```
Demo: Hastad broadcast attack visualiser.
```
```
 Three recipient panels, each showing their modulusNiand a \received ciphertext"
ci=m^3 modNi.
 An \Attacker" panel below runs CRT on the three ciphertexts live and displays the
recovered integerm^3.
 Click \Cube root." The integer cube root is computed and the plaintextmis
revealed | matching the original.
 A \Use PKCS padding" toggle re-runs the attack with padded ciphertexts. The
attack fails: CRT still works but the cube root is not an integer, and the padded
garbage is displayed.
```
```
Toy parameters:64-bitNifor instant computation. Graders check that the plaintext
is recovered in unpadded mode and fails in padded mode.
```
### 4.5 PA #15 | Digital Signatures.

```
Intuition
Digital signatures are the public-key analogue of MACs. Alice signs a message with her
private key; anyone can verify with herpublic key. Unlike MACs, signatures provide
non-repudiation|Alice cannot deny having signed a message, because only she has
the private key.
```

```
Digital Signature Denition
```
```
(Gen;Sign;Vrfy) satisfying:
```
```
 Gen(1n)!(vk; sk): verication key and signing key.
 Signsk(m)!: signature onm.
 Vrfyvk(m; )!f 0 ; 1 g: 1 iff valid.
```
```
Security (EUF-CMA):No PPT adversary with access to signing oracle can forge a
valid (m; ) for anymnot previously signed.
```
RSA Signature (textbook):=mdmodN, verify: e=?mmodN.
In practice:Always sign the hash of the message:=H(m)dmodN.

```
PA #15 | What You Must Implement
```
1. RSA signature scheme: Implement sign(sk, m) = H(m)dmodN and
    verify(vk, m, sigma)= (emodN =? H(m)). Use your PA#12 RSA and your
    PA#8 hash. Signing rawmwithout hashing is not acceptable (vulnerable to existen-
    tial forgery).
2. Hash-then-sign: Explicitly hash the message before signing. Demonstrate that with-
    out hashing, an adversary can forge a signature onm 1 m 2 given signatures onm 1
    andm 2 (multiplicative homomorphism attack on raw RSA).
3. EUF-CMA game: Implement the signing oracle game. Show that after seeing up
    to 50 signed messages, the adversary cannot produce a valid (m; ) for any newm
    (with overwhelming probability).
4. ElGamal signature (alternative): Optionally also implement Schnorr or ElGamal
    signatures using your PA#16 group, providing a DLP-based alternative to RSA-based
    signing.
5. Interface: ExposeSign(sk, m) -> sigmaandVerify(vk, m, sigma) -> boolfor
    use in PA#17.

```
PA #15 | Interactive Demo Deliverable
```
```
Demo: Sign and verify live.
```
```
 A text input for a message and a \Sign" button. The signature=H(m)dmodN
is displayed in hex.
 A \Verify" button checksemodN=? H(m), showing the intermediate values and
a green \Valid" or red \Invalid" result.
 A \Tamper" button 
ips one bit of the message after signing; verication immedi-
ately fails.
 \Raw RSA sign (no hash)" toggle: signsmdirectly without hashing, then demon-
strates the multiplicative forgery | given signatures onm 1 andm 2 , compute a
valid signature onm 1 m 2 without the private key.
```

### 4.6 PA #16 | ElGamal Public-Key Cryptosystem

```
Intuition
ElGamal is a PKC based directly on the hardness of DLP. Unlike RSA (which needs new
number-theoretic assumptions), ElGamal security reduces cleanly to DDH (Decisional
Diffie-Hellman). Its structure closely mirrors the DH key exchange.
```
```
ElGamal Cryptosystem
```
```
Setup:Cyclic groupGof prime orderqwith generatorg.
Key Generation:
```
1. Sample private keyx Zq.
2. Set public keyh=gx.

```
Encryptionofm 2 G:
```
1. Sampler Zq.
2. OutputC= (gr; mhr) = (gr; mgxr).

```
Decryptionof (c 1 ; c 2 ):
```
1. Computem=c 2 =cx 1 =mgxr=grx=m.

```
Security Claim
```
```
ElGamal is CPA-secure under the DDH assumption. The ciphertext (gr; mhr) is indis-
tinguishable from (gr;random) when DDH holds.
```
Warning: Standard ElGamal is also malleable (like textbook RSA)|it is only CPA-secure,
not CCA-secure.

```
PA #16 | What You Must Implement
```
1. Key generation: Implementelgamalkeygen()using your PA#11 group (primep,
    generatorg, orderq). Samplex Zq, compute public keyh=gxmodp. Output
    (sk=x, pk=(p,g,q,h)).
2. Encryption and decryption: ImplementElGamalEnc(pk, m)| sample freshr
    Zq, return (grmodp; mhrmodp) | andElGamalDec(sk, c1, c2)=c 2 =cx 1 modp.
3. Malleability attack: Given ciphertext (c 1 ; c 2 ) for unknownm, construct (c 1 ; 2 c 2 mod
    p) which decrypts to 2m, without knowingmorx. Show this breaks CCA security.
4. CPA game: Implement the IND-CPA game for ElGamal. Conrm the adversary
    advantage is0 when DDH is hard (large group), and demonstrate a distinguisher
    succeeds when the group is tiny (e.g.,q 210 ).
5. Interface: ExposeEnc(pk, m) -> (c1, c2)andDec(sk, c1, c2) -> mfor use in
    PA#17 and PA#18.

```
PA #16 | Interactive Demo Deliverable
```
```
Demo: ElGamal malleability.
 Encrypt a plaintext group elementm(entered as an integer). Ciphertext (c 1 ; c 2 ) is
```

```
shown.
 A \Multiplyc 2 by 2" button produces (c 1 ; 2 c 2 modp) | a new valid ciphertext.
Click \Decrypt." The result 2mis shown, demonstrating malleability.
 A counter shows how many times this trick succeeds (should be 100%).
 A side panel shows the CPA game: encrypt a challenge, submit a modied cipher-
text to the decryption oracle, conrm 2mcomes back, demonstrating why ElGamal
fails CCA.
```
```
Conrm that Dec(c 1 ; 2 c 2 ) = 2Dec(c 1 ; c 2 ) for any message.
```
### 4.7 PA #17 | CCA-Secure PKC

```
Intuition
Textbook RSA and basic ElGamal are malleable: givenC= (gr; mhr), one can produce
C′= (gr; 2 mhr) encrypting 2mwithout knowingm. CCA security defeats this. We
combine Digital Signatures (PA#15) with PKC (PA#16) in theSign-then-Encrypt-
then-MACorFujisaki-Okamotoparadigm.
```
```
Signcryption Construction (PA#15 + PA#16)
```
```
Encrypt:CE ElGamalpk(m)
Sign: Signsk(CE)
Output:(CE; )
Decrypt:
```
1. Verify Vrfyvk(CE; ) = 1 (reject if not)
2. Output ElGamal:Decsk(CE)

```
plaintextm ElGamalCE Sign
```
```
(CE; )
```
```
Vrfy sig. & then Decrypt
```
```
PA #17 | What You Must Implement
```
1. Signcrypt (Encrypt-then-Sign): ImplementCCAPKCEnc(pkenc, sksign, m):
    rst encryptmwith your PA#16 ElGamal (or PA#12 RSA), then sign the ciphertext
    with your PA#15 digital signature. Return (CE; ).
2. Verify-then-Decrypt: Implement CCAPKCDec(skenc, vksign, CE, sigma):
    callVerifyrst; if the signature is invalid return?; otherwise callDec. The sig-
    nature checkmust precededecryption | this ordering is not optional.
3. CCA2 game for PKC: Implement the IND-CCA2 game with a decryption oracle.
    Show that your scheme correctly rejects modied ciphertexts (the signature fails), so


```
the decryption oracle is useless to the adversary.
```
4. Contrast with CPA-only: Demonstrate the malleability attack from PA#16 on
    plain ElGamal: the adversary submits a modied ciphertext to the decryption oracle
    and gets back 2m. Show the same attack fails on your PA#17 scheme because the
    signature is invalid on the modied ciphertext.
5. Full lineage check: Your submission must trace the entire dependency chain in code:
    PA#17 calls PA#15 (your signatures) and PA#16 (your ElGamal), which call PA#12
    and PA#11, which call PA#13. No library substitutions at any layer.

PA #17 | Interactive Demo Deliverable

Demo: CCA malleability blocked.

```
 Encrypt a message using Encrypt-then-Sign. The ciphertext (CE; ) is shown.
 A \Tamper withCE" button (simulating the CCA attacker) modies one byte of
CE.
 Submit to decryption oracle. The app shows signature verication ring rst |
\Signature invalid, decryption aborted, output?." The plaintext never decrypts.
 Contrast panel (plain ElGamal): the same tamper goes through, and 2mis re-
turned.
```
Any tampered ciphertext returns?. Untampered ciphertext decrypts correctly.


## 5 Part IV: Secure Multi-Party Computation (MPC)

```
Intuition
The ultimate goal:Two mutually distrusting parties Alice and Bob hold private inputs
xandy. Can they jointly computef(x; y)withoutrevealing their inputs to each other?
Yao's Garbled Circuits and the GMW protocol say:yes, and the foundation isOblivious
Transfer (OT).
```
```
Alice (input x) Bob (input y)
```
```
f(x; y)
```
```
Both learnf(x; y), neither learns the other's input
```
```
Secure 2-Party Computation
```
### 5.1 PA #18 | Oblivious Transfer (OT)

```
Lineage Requirement
```
```
The PKC used in this OT implementationmust be your own implementation from
PA#12 (RSA) or PA#16 (ElGamal). Importing any external PKC library violates
the no-library rule and breaks the reduction chain.
```
```
Standalone Concept: Oblivious Transfer
```
```
1-out-of-2 OT:Sender has bits (m 0 ; m 1 ). Receiver has choice bitb2 f 0 ; 1 g. The OT
protocol ensures:
```
```
 Receiver learnsmbandnothingaboutm 1 b.
 Sender learnsnothingaboutb.
```
```
This is theatomic building blockof all MPC.
```
```
OT from PKC (Bellare-Micali)
```
```
Setup:PKC scheme (Gen;Enc;Dec).
```
1. Receiver generatestwo key pairs: (pk 0 ; sk 0 ) and (pk 1 ; sk 1 ), but only keepsskb
    (discardssk 1 b, or constructspk 1 bwithout knowing its secret key using a trap-
    door).
2. Receiver sends both (pk 0 ; pk 1 ) to Sender.
3. Sender encrypts: sendsC 0 = Encpk 0 (m 0 ) andC 1 = Encpk 1 (m 1 ).
4. Receiver decryptsCb= Decskb(Cb) to getmb; cannot decryptC 1 b.


```
Receiver (choiceb) Sender(m 0 ; m 1 )
(pk 0 ; pk 1 )
```
```
C 0 = Encpk 0 (m 0 ); C 1 = Encpk 1 (m 1 )
```
```
Receiver decryptsCb
getsmbonly
```
```
Sender never learnsb
```
PA #18 | What You Must Implement

1. 1-out-of-2 OT from your PKC: Implement the full Bellare-Micali OT protocol
    using your own PA#16 ElGamal (or PA#12 RSA). Your implementation must have
    two clearly separated roles:
        OTReceiverStep1(b) -> (pk0, pk1, state): Receiver generatespkbhon-
          estly (keepingskb) and constructspk 1 bwithout a trapdoor (e.g., by choosing
          a random group element as the public key, for which no private key is known).
          Returns both public keys and private state.
        OTSenderStep(pk0, pk1, m0, m1) -> (C0, C1): Sender encrypts both
          messages and returns both ciphertexts.
        OTReceiverStep2(state, C0, C1) -> mb: Receiver decrypts onlyCbusing
          skb.
2. Receiver privacy: Demonstrate that the sender, given (pk 0 ; pk 1 ), cannot determine
    b| becausepk 1 bwas constructed without a trapdoor, both keys are computationally
    indistinguishable.
3. Sender privacy: Demonstrate that the receiver cannot decryptC 1 b| they have
    nosk 1 b. For small parameters, attempt a brute-force decryption and show it requires
    solving DLP or factoring.
4. Correctness: Run 100 trials with randomb2 f 0 ; 1 gand random (m 0 ; m 1 ). Verify
    that the receiver always recoversmbcorrectly.
5. Interface: Expose the three-step API above so PA#19 can call OT as a black box
    with no knowledge of the underlying PKC.

PA #18 | Interactive Demo Deliverable

Demo: Play the OT receiver.The student is Bob:

```
 Alice's panel (left, greyed out): holds two messagesm 0 andm 1 , hidden.
 Bob's panel (right, interactive): student clicks \Choose 0" or \Choose 1."
 The OT protocol runs step-by-step with a message log showing: key pairs generated,
(pk 0 ; pk 1 ) sent to Alice,C 0 andC 1 received,Cbdecrypted.
 Result:mbis revealed to Bob. m 1 bremains hidden (shown as \??"). A \Cheat
attempt" button tries to decryptC 1 band shows the failure.
```
Choose 0 and 1 in separate runs; conrm correct message received each time and the
other is hidden.


### 5.2 PA #19 | Secure AND Gate.

```
Intuition
If we can evaluate AND securely, we can evaluate any boolean function securely (since
AND and XOR form afunctionally completebasis). The key trick: use OT to imple-
ment AND without either party revealing their input bit.
```
```
Secure AND from OT
Alice holdsa2f 0 ; 1 g, Bob holdsb2f 0 ; 1 g. Goal: both learna^b.
```
1. Alice acts asOT senderwith messages (m 0 ; m 1 ) = (0; a).
2. Bob acts asOT receiverwith choice bitb.
3. Bob receivesmb=ab=a^b.

```
Security:Bob learns onlya^b(nota). Alice learns nothing aboutb(OT guarantee).
```
```
Alice:a Bob:b
```
```
OT Protocol (PA#18)
```
```
Output:a^b
```
```
(0; a) choiceb
```
```
mb=a^b
```
```
PA #19 | What You Must Implement
```
1. Secure AND from OT: ImplementSecureAND(a, b)using your PA#18 OT as a
    subroutine. Alice plays OT sender with messages (m 0 ; m 1 ) = (0; a); Bob plays OT
    receiver with choice bitb; Bob receivesmb=a^b. Both parties then locally output
    a^b.
2. Secure XOR (free): ImplementSecureXOR(a, b): this requiresnoOT call. Alice
    and Bob each locally hold a share; the XOR of their shares equals the result. Imple-
    ment additive secret sharing overZ 2 : Alice sendsr f 0 ; 1 gto Bob; Alice's share is
    ar, Bob's share isbr; the output is the XOR of both shares. No information
    about either party's input is revealed.
3. NOT gate (free): ImplementSecureNOT(a): Alice locally 
ips her share. No
    communication needed.
4. Privacy proof (informal): ForSecureAND, write a brief argument (code comment
    or README) showing: (a) Bob learns nothing aboutabeyonda^b(follows from OT
    receiver privacy); (b) Alice learns nothing aboutb(follows from OT sender privacy).
5. Truth table test: Verify all four input combinations (a; b)2f 00 ; 01 ; 10 ; 11 gproduce
    the correct AND and XOR outputs across 50 runs each. Conrm no party can recover
    the other's input bit from the protocol transcript alone.
6. Interface: ExposeAND(a, b) -> bitandXOR(a, b) -> bitso that PA#20 can
    compose them into arbitrary circuits.


```
PA #19 | Interactive Demo Deliverable
```
```
Demo: Secure AND step-by-step.
```
```
 Alice panel: student enters bita2f 0 ; 1 g.
 Bob panel: student enters bitb2f 0 ; 1 g.
 Click \Compute AND." A step-log shows: Alice sets up OT messages (0; a), Bob
runs OT receiver with choiceb, Bob receivesmb=a^b.
 The transcript (all messages exchanged) is shown. A \What does Alice learn?" and
\What does Bob learn?" summary conrms neither party sees the other's input.
 All four (a; b) combinations have a \Run all" button that conrms correct AND
output for each.
```
```
Run all 4 combinations; verify outputs match AND truth table and transcript reveals
nothing extra.
```
### 5.3 PA #20 | All 2-Party Secure Computation (Yao / GMW)

```
Lineage Requirement
```
```
PA#20 must be built usingyour own PA#19 (Secure AND)andyour own PA#18
(OT), which in turn usesyour own PKC from PA#12/#16. The entire MPC stack
must trace back to your own implementations with no library substitutions at any layer.
```
```
The Grand Theorem: MPC Completeness
```
```
Given Secure AND (PA#19) and Secure XOR (free via additive secret sharing), we can
securely evaluateanypolynomial-time computable 2-party functionf(x; y).
Why?Any boolean circuit can be expressed using AND and XOR gates (NOT is free).
Compose our secure gates to get a secure circuit. This is the essence of Yao's Garbled
Circuits.
```
```
Yao's Garbled Circuit (Sketch)
```
1. Alicegarbles the circuitCcomputingf: for each gate, she creates an encrypted
    truth table using OT-based keys.
2. Alice sends the garbled circuitC~and her input labels to Bob.
3. Bob uses OT (PA#18) to get labels forhisinput bits without Alice learning Bob's
    input.
4. Bob evaluatesC~gate by gate (in topological order) and learns the output.


```
x 1
```
```
x 2
```
```
y 1
```
```
y 2
```
```
AND
```
```
XOR
```
```
AND
```
```
XOR
```
```
OUT
```
```
f(x 1 ; x 2 ; y 1 ; y 2 )
```
```
secure AND (PA#19)
```
Security Claim

Using Secure AND (from OT, from PKC) and Secure XOR (free), PA#20 implements
any boolean circuit securely. This completes the full cryptographic stack: from OWF at
the base to arbitrary secure computation at the top.

PA #20 | What You Must Implement

1. Boolean circuit evaluator: Implement aCircuitclass that represents any boolean
    function as a directed acyclic graph (DAG) of AND, XOR, and NOT gates. Nodes
    store gate type and wire indices; the circuit takes a list of input bits and evaluates to
    output bits.
2. Secure circuit evaluation: ImplementSecureEval(circuit, xAlice, yBob)
    which evaluates the circuit on Alice's inputxand Bob's inputy usingonlyyour
    PA#19AND,XOR, andNOTgate primitives. Traverse the circuit in topological order;
    call the corresponding secure gate for each node.
3. Three mandatory test circuits: You must implement and securely evaluate the
    following:
        Millionaire's Problem: Alice has integerx, Bob has integery. Securely com-
          putex > y(who is richer) without revealing the actual values. Implement the
          comparison circuit overn-bit integers using AND and XOR gates.
        Secure equality test: Computex= y(bit-wise equality of n-bit integers)
          without revealingxory.
        Secure bit-addition: Compute the sumx+yof twon-bit integers modulo 2n,
          revealing only the result.
4. Privacy verication: For each of the three circuits above, conrm that neither party
    learns anything beyond the output. Concretely: log all messages exchanged during
    the protocol; show that the transcript is simulatable (i.e., it could have been generated
    from the output alone, without the other party's input).
5. End-to-end lineage: The evaluation of a single AND gate must ultimately trigger:
    PA#19 AND!PA#18 OT!PA#16 ElGamal (or PA#12 RSA)!PA#13 Miller-
    Rabin (for key generation). Provide a call-stack trace in your README demonstrating
    this full chain for at least one gate evaluation.
6. Performance: Report the number of OT calls required to evaluate each of the three
    circuits above, and the total wall-clock time forn= 8-bit inputs. This gives a concrete
    sense of the cost of MPC.


PA #20 | Interactive Demo Deliverable

Demo: Millionaire's problem live.

```
 Alice panel: slider for her wealthx(1{100, hidden from Bob's panel).
 Bob panel: slider for his wealthy(1{100, hidden from Alice's panel).
 Click \Who is richer?" The comparison circuit evaluates gate by gate; a progress
bar shows gates completed.
 Result: \Alice is richer" / \Bob is richer" / \Equal" | displayed to both. The
actual valuesxandyare never revealed.
 A \Circuit trace" expandable section shows the AND/XOR gates evaluated and
the output wire values (butnotthe input wires of the other party).
```
Toy parameters:n= 4-bit comparison (16 possible values). Fast enough to animate
gate-by-gate. Setx= 7; y= 12; conrm Bob is richer without Alice's panel revealing 7.


## 6 Summary: The Full Reduction Chain

```
OWF (PA#1)
any OWF, DLP, AES
```
```
PRG (PA#1) PRF (PA#2, GGM)
```
```
PRP (AES, PA#4) MAC (PA#5)
```
```
CRHF (PA#7+8)
Birthday 
oor: PA#9
```
```
HMAC (PA#10)
Birthday 
oor: PA#9
```
```
CPA-Enc (PA#3)
```
```
CCA-Enc (PA#6+10)
```
```
PKC (DH PA#11, RSA PA#12, ElGamal PA#16)
CRT attack: PA#14
```
```
Digital Sig (PA#15) CCA-PKC (PA#17)
```
```
OT (PA#18)
```
```
Secure AND (PA#19)
```
```
All 2-Party MPC (PA#20)
```
```
PA#10
```
```
HMAC bridge
```
```
Minicrypt Clique
```
```
Cryptomania
```
```
MPC Land
```

Assignment Index

```
PA Topic Must use your own impl. of Bidir.
#0 Minicrypt Clique Web Explorer (React) Stubs PA#1{#10 (incremental)
#1 OWF + PRG | ✓
#2 PRF (GGM tree) #1 (or self-impl. AES) ✓
#3 CPA-secure encryption #2
#4 Modes of Operation (CBC/OFB/CTR) #3
#5 Secure MACs (PRF-MAC, CBC-MAC) #2 (or self-impl. AES)
#6 CCA-secure encryption #3 + #5
#7 Merkle-Damgrd Transform |
#8 DLP-based CRHF #7
#9 Birthday Attack (collision nding) #8 (truncated)
#10 HMAC + Encrypt-then-HMAC #8 + #3 ✓
#11 Diffie-Hellman SKE #13
#12 Textbook RSA+ PKCS#1 v1.5 #13
#13 Miller-Rabin Primality |
#14 CRT + Hastad Broadcast Attack #12 + #13
#15 Digital Signatures #12 or #16
#16 ElGamal PKC #11
#17 CCA-Secure PKC #15 + #16
#18 Oblivious Transfer #12 or #16 (your PKC!)
#19 Secure AND #18
#20 All 2-party MPC #19 + #18
```
Bidir.(✓) = bidirectional reduction required (bothA)BandB)Amust be imple-
mented). PA#1{#2 cover the core Minicrypt clique; PA#10 adds the CRHF$MAC
bridge via HMAC. All other PAs require only a forward construction.


