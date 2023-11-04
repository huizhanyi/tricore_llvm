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
### TriCoreTargetMachine
```
32 class TriCoreTargetMachine : public LLVMTargetMachine {
```
继承自LLVMTargetMachine基类。定义在include/llvm/Target/TargetMachine.h
```
245 class LLVMTargetMachine : public TargetMachine {
生成遍配置，生成代码生成流水线。虚函数，可以在基类重新定义。
262   virtual TargetPassConfig *createPassConfig(PassManagerBase &PM);
```
```
33   TriCoreSubtarget Subtarget;
这里TriCoreSubtarget继承自TargetSubtargetInfo。
45   virtual const TargetSubtargetInfo *
46   getSubtargetImpl(const Function &) const override {
47     return &Subtarget;
48   }
```

TriCoreTargetMachine.cpp
```
// Force static initialization.
extern "C" void LLVMInitializeTriCoreTarget() {
  RegisterTargetMachine<TriCoreTargetMachine> X(TheTriCoreTarget);
}
```
这里用TriCoreTargetMachine实例化函数Allocator，然后，将Allocator登记给TheTriCoreTarget
```
template <class TargetMachineImpl> struct RegisterTargetMachine {
  RegisterTargetMachine(Target &T) {
    TargetRegistry::RegisterTargetMachine(T, &Allocator);
  }

private:
  static TargetMachine *Allocator(const Target &T, const Triple &TT,
                                  StringRef CPU, StringRef FS,
                                  const TargetOptions &Options, Reloc::Model RM,
                                  CodeModel::Model CM, CodeGenOpt::Level OL) {
    return new TargetMachineImpl(T, TT, CPU, FS, Options, RM, CM, OL);
  }
};
```
这里通过调用Allocator生成TargetMachine,即TriCoreTargetMachine。

代码里找不到哪里调用了LLVMInitializeTriCoreTarget，调试llc分析一下。
```
Breakpoint 1, LLVMInitializeTriCoreTarget () at /home/yhz/tricore_llvm/llvm-3.7.0.src/lib/Target/TriCore/TriCoreTargetMachine.cpp:97
97      extern "C" void LLVMInitializeTriCoreTarget() {
(gdb) bt
#0  LLVMInitializeTriCoreTarget () at /home/yhz/tricore_llvm/llvm-3.7.0.src/lib/Target/TriCore/TriCoreTargetMachine.cpp:97
#1  0x0000555555f02652 in llvm::InitializeAllTargets () at /home/yhz/tricore_llvm/build/include/llvm/Config/Targets.def:35
#2  0x0000555555efd252 in main (argc=8, argv=0x7fffffffe1e8) at /home/yhz/tricore_llvm/llvm-3.7.0.src/tools/llc/llc.cpp:182
```
InitializeAllTargets() -> LLVMInitializeTriCoreTarget
llvm/Support/TargetSelect.h
```
63   inline void InitializeAllTargets() {
64     // FIXME: Remove this, clients should do it.
这里先调用后端的LLVMInitializeTriCoreTargetInfo
65     InitializeAllTargetInfos();
66
看这里，会调用所有后端的LLVMInitialize函数,包括LLVMInitializeTriCoreTarget。
67 #define LLVM_TARGET(TargetName) LLVMInitialize##TargetName##Target();
68 #include "llvm/Config/Targets.def"
69   }
```
这里LLVMInitializeTriCoreTargetInfo定义为
```
extern "C" void LLVMInitializeTriCoreTargetInfo() {
  RegisterTarget<Triple::tricore> X(TheTriCoreTarget, "tricore", "TriCore");
}
```
Triple::tricore是外部增加的一个枚举类型。
```
868 template <Triple::ArchType TargetArchType = Triple::UnknownArch,
869           bool HasJIT = false>
870 struct RegisterTarget {
871   RegisterTarget(Target &T, const char *Name, const char *Desc) {
872     TargetRegistry::RegisterTarget(T, Name, Desc, &getArchMatch, HasJIT);
873   }
874
875   static bool getArchMatch(Triple::ArchType Arch) {
876     return Arch == TargetArchType;
877   }
878 };
```
这里实际调用TargetRegistry::RegisterTarget函数，登记了TheTriCoreTarget目标。
TheTriCoreTarget是一个全局变量，没有特别初始化。TargetRegistry::RegisterTarget函数将对应对象进行初始化，增加名字、描述等信息。
#### Subtarget信息
实际上很多信息TriCoreTargetMachine是通过Subtarget包含的，而不是直接定义在TargetMachine中。也就是字段
```
TriCoreSubtarget Subtarget;
```
检查了几个后端，都是这样的。
```
class TriCoreSubtarget : public TriCoreGenSubtargetInfo {
  virtual void anchor();

private:
  const DataLayout DL;       // Calculates type size & alignment.
  TriCoreInstrInfo InstrInfo;
  TriCoreTargetLowering TLInfo;
  TriCoreSelectionDAGInfo TSInfo;
  TriCoreFrameLowering FrameLowering;
  InstrItineraryData InstrItins;

  // UseSmallSection - Small section is used.
        bool UseSmallSection;

public:
  /// This constructor initializes the data members to match that
  /// of the specified triple.
  ///
  TriCoreSubtarget(const Triple &TT, StringRef CPU,
               StringRef FS, TriCoreTargetMachine &TM);
```
```
TriCoreSubtarget::TriCoreSubtarget(const Triple &TT, StringRef CPU, StringRef FS,
                           TriCoreTargetMachine &TM)
    : TriCoreGenSubtargetInfo(TT, CPU, FS),
      DL("e-m:e-p:32:32-i64:32-a:0:32-n32"),
      InstrInfo(), TLInfo(TM), TSInfo(), FrameLowering() {

         UseSmallSection = UseSmallSectionOpt;

}
```
SubTarget的初始化调用在TargetMachine的构造函数中
```
TriCoreTargetMachine::TriCoreTargetMachine(const Target &T, const Triple &TT,
                                   StringRef CPU, StringRef FS,
                                   const TargetOptions &Options,
                                   Reloc::Model RM, CodeModel::Model CM,
                                   CodeGenOpt::Level OL)
    : LLVMTargetMachine(T,
      computeDataLayout(TT, CPU, Options),
      TT, CPU, FS,
      Options, RM, CM, OL),
      Subtarget(TT, CPU, FS, *this),
      TLOF(make_unique<TargetLoweringObjectFileELF>()) {
  initAsmInfo();
}
```
TriCoreSubtarget初始化时，对内部数据的构造器进行了调用。例如
```
DL("e-m:e-p:32:32-i64:32-a:0:32-n32"), InstrInfo(), TLInfo(TM), TSInfo(), FrameLowering() 
```
相关定义如下
```
const DataLayout DL;       // Calculates type size & alignment.
TriCoreInstrInfo InstrInfo;
TriCoreTargetLowering TLInfo;
TriCoreSelectionDAGInfo TSInfo;
TriCoreFrameLowering FrameLowering;
InstrItineraryData InstrItins;
```
