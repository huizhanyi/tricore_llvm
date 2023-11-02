## TriCore后端分析笔记
### 关于PASS
后端组成了一系列的PASS，TriCore后端增加了一些PASS，但是PASS在哪里呢？使用如下命令打印后端遍
```
$ llc -debug-pass=Structure -march=tricore -relocation-model=pic -filetype=asm 20.global_test_arm.bc -o 20.global_test_arm-1.s
Pass Arguments:  -targetlibinfo -tti -targetpassconfig -no-aa -tbaa -scoped-noalias -assumption-cache-tracker -basicaa -collector-metadata -machinemoduleinfo -machine-branch-prob -verify -domtree -loops -loop-simplify -scalar-evolution -iv-users -loop-reduce -gc-lowering -shadow-stack-gc-lowering -unreachableblockelim -domtree -consthoist -partially-inline-libcalls -codegenprepare -rewrite-symbols -lowerinvoke -unreachableblockelim -safe-stack -stack-protector -verify -domtree -loops -branch-prob -expand-isel-pseudos -tailduplication -opt-phis -machinedomtree -slotindexes -stack-coloring -localstackalloc -dead-mi-elimination -machinedomtree -machine-loops -machinelicm -machine-cse -machinepostdomtree -machine-block-freq -machine-sink -peephole-opts -dead-mi-elimination -processimpdefs -unreachable-mbb-elimination -livevars -machinedomtree -machine-loops -phi-node-elimination -twoaddressinstruction -slotindexes -liveintervals -simple-register-coalescing -machine-scheduler -machine-block-freq -livedebugvars -livestacks -virtregmap -liveregmatrix -edge-bundles -spill-code-placement -virtregrewriter -stack-slot-coloring -machinelicm -prologepilog -machine-block-freq -branch-folder -tailduplication -machine-cp -postrapseudos -machinedomtree -machine-loops -post-RA-sched -gc-analysis -machine-block-freq -block-placement -stackmap-liveness -machinedomtree -machine-loops
Target Library Information
Target Transform Information
Target Pass Configuration
No Alias Analysis (always returns 'may' alias)
Type-Based Alias Analysis
Scoped NoAlias Alias Analysis
Assumption Cache Tracker
Basic Alias Analysis (stateless AA impl)
Create Garbage Collector Module Metadata
Machine Module Information
Machine Branch Probability Analysis
  ModulePass Manager
    FunctionPass Manager
      Module Verifier
      Dominator Tree Construction
      Natural Loop Information
      Canonicalize natural loops
      Scalar Evolution Analysis
      Loop Pass Manager
        Induction Variable Users
        Loop Strength Reduction
      Lower Garbage Collection Instructions
      Shadow Stack GC Lowering
      Remove unreachable blocks from the CFG
      Dominator Tree Construction
      Constant Hoisting
      Partially inline calls to library functions
      CodeGen Prepare
    Rewrite Symbols
    FunctionPass Manager
      Lower invoke and unwind, for unwindless code generators
      Remove unreachable blocks from the CFG
      Safe Stack instrumentation pass
      Insert stack protectors
      Module Verifier
      Machine Function Analysis
      Dominator Tree Construction
      Natural Loop Information
      Branch Probability Analysis
      TriCore DAG->DAG Pattern Instruction Selection
      Expand ISel Pseudo-instructions
      Tail Duplication
      Optimize machine instruction PHIs
      MachineDominator Tree Construction
      Slot index numbering
      Merge disjoint stack slots
      Local Stack Slot Allocation
      Remove dead machine instructions
      MachineDominator Tree Construction
      Machine Natural Loop Construction
      Machine Loop Invariant Code Motion
      Machine Common Subexpression Elimination
      MachinePostDominator Tree Construction
      Machine Block Frequency Analysis
      Machine code sinking
      Peephole Optimizations
      Remove dead machine instructions
      Process Implicit Definitions
      Remove unreachable machine basic blocks
      Live Variable Analysis
      MachineDominator Tree Construction
      Machine Natural Loop Construction
      Eliminate PHI nodes for register allocation
      Two-Address instruction pass
      Slot index numbering
      Live Interval Analysis
      Simple Register Coalescing
      Machine Instruction Scheduler
      Machine Block Frequency Analysis
      Debug Variable Analysis
      Live Stack Slot Analysis
      Virtual Register Map
      Live Register Matrix
      Bundle Machine CFG Edges
      Spill Code Placement Analysis
      Greedy Register Allocator
      Virtual Register Rewriter
      Stack Slot Coloring
      Machine Loop Invariant Code Motion
      Prologue/Epilogue Insertion & Frame Finalization
      Machine Block Frequency Analysis
      Control Flow Optimizer
      Tail Duplication
      Machine Copy Propagation Pass
      Post-RA pseudo instruction expansion pass
      MachineDominator Tree Construction
      Machine Natural Loop Construction
      Post RA top-down list latency scheduler
      Analyze Machine Code For Garbage Collection
      Machine Block Frequency Analysis
      Branch Probability Basic Block Placement
      StackMap Liveness Analysis
      MachineDominator Tree Construction
      Machine Natural Loop Construction
      TriCore Assembly Printer
```
对于TriCore DAG->DAG Pattern Instruction Selection遍，在哪里生成的呢？搜索字符串发现是在文件TriCoreISelDAGToDAG.cpp的TriCoreDAGToDAGISel类中完成打印，而这个类定义如下
```
class TriCoreDAGToDAGISel : public SelectionDAGISel
```
这里跟踪一下可以看出SelectionDAGISel继承了MachineFunctionPass，进一步继承自FunctionPass。因此TriCoreDAGToDAGISel本身就是一个遍结构类。
文件结束生成了这个类（遍）
```
FunctionPass *llvm::createTriCoreISelDag(TriCoreTargetMachine &TM,
                CodeGenOpt::Level OptLevel) {
        return new TriCoreDAGToDAGISel(TM, OptLevel);
}
```
createTriCoreISelDag函数在TriCoreTargetMachine.cpp
```
89 bool TriCorePassConfig::addInstSelector() {
90   addPass(createTriCoreISelDag(getTriCoreTargetMachine(), getOptLevel()));
91   return false;
92 }
```
TriCorePassConfig定义如下
```
68 class TriCorePassConfig : public TargetPassConfig {
```
TargetPassConfig本身继承自ImmutablePass（继承自ModulePass）
```
class TargetPassConfig : public ImmutablePass {
```
所以TriCorePassConfig是一个ModulePass

TriCoreTargetMachine定义的createPassConfig函数会生成一个TriCorePassConfig对象
```
class TriCoreTargetMachine : public LLVMTargetMachine
  /// Pass Pipeline Configuration
  virtual TargetPassConfig *createPassConfig(legacy::PassManagerBase &PM) override;
```
而TriCoreTargetMachine在下面的代码中完成注册。
```
// Force static initialization.
extern "C" void LLVMInitializeTriCoreTarget() {
  RegisterTargetMachine<TriCoreTargetMachine> X(TheTriCoreTarget);
}
```
另外一个PASS是TriCoreAsmPrinter
```
class TriCoreAsmPrinter : public AsmPrinter {
```
```
class AsmPrinter : public MachineFunctionPass {
```
可以看出这也是一个Pass。
其他PASS的定义不在TriCore目标的定义中，由外部定义，大部分在lib/CodeGen目录。
