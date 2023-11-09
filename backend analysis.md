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
#### 寄存器（Register）信息
TriCoreRegisterInfo.td定义了系统的寄存器信息。
TriCoreRegisterInfo.h/cpp定义了一起其他寄存器信息。
```
44 const uint16_t *
45 TriCoreRegisterInfo::getCalleeSavedRegs(const MachineFunction *MF) const {
46   static const uint16_t CalleeSavedRegs[] =
47   { 0 };
48   return CalleeSavedRegs;
49 }
```
这里继承的虚函数返回CalleeSavedRegister信息，对于CalleeSavedRegister，Caller可以假定这些寄存器的信息经过函数调用后，值会被保留。
TriCore的upper上下文的寄存器调用函数前自动会被保留，调用完毕会自动恢复。因此这里认为不需要处理CalleeSavedRegister。
但是这里TriCore的处理有些矛盾，按照这里的说法，upper上下文的寄存器是CalleeSaved的寄存器。但是后面的函数getCallPreservedMask大部分是lower上下文的寄存器，是通过TriCoreCallingconv.td文件中的CC_SAVE定义的。这两个函数表示的内存似乎是重合的？检查对这两个函数的定义
llvm/Target/TargetRegisterInfo.h
```
/// getCalleeSavedRegs - Return a null-terminated list of all of the
/// callee saved registers on this target. The register should be in the
/// order of desired callee-save stack frame offset. The first register is
/// closest to the incoming stack pointer if stack grows down, and vice versa.
///
virtual const MCPhysReg*
getCalleeSavedRegs(const MachineFunction *MF) const = 0;

/// getCallPreservedMask - Return a mask of call-preserved registers for the
/// given calling convention on the current function.  The mask should
/// include all call-preserved aliases.  This is used by the register
/// allocator to determine which registers can be live across a call.
///
/// The mask is an array containing (TRI::getNumRegs()+31)/32 entries.
/// A set bit indicates that all bits of the corresponding register are
/// preserved across the function call.  The bit mask is expected to be
/// sub-register complete, i.e. if A is preserved, so are all its
/// sub-registers.
///
/// Bits are numbered from the LSB, so the bit for physical register Reg can
/// be found as (Mask[Reg / 32] >> Reg % 32) & 1.
///
/// A NULL pointer means that no register mask will be used, and call
/// instructions should use implicit-def operands to indicate call clobbered
/// registers.
///
virtual const uint32_t *getCallPreservedMask(const MachineFunction &MF,
                                             CallingConv::ID) const {
/// getReservedRegs - Returns a bitset indexed by physical register number
/// indicating if a register is a special register that has particular uses
/// and should be considered unavailable at all times, e.g. SP, RA. This is
/// used by register scavenger to determine what registers are free.
virtual BitVector getReservedRegs(const MachineFunction &MF) const = 0;
```
根据上述两个函数的注释，感觉calleesavedregister和call-preserved register含义有重叠。但是按照TriCore的实现，则完全不相交。
其他有些后端没有定义函数getCallPreservedMask。
```
 53 const MCPhysReg *
 54 Cpu0RegisterInfo::getCalleeSavedRegs(const MachineFunction *MF) const {
 55   return CSR_O32_SaveList;
 56 }
 57
 58 const uint32_t *
 59 Cpu0RegisterInfo::getCallPreservedMask(const MachineFunction &MF,
 60                                        CallingConv::ID) const {
 61   return CSR_O32_RegMask;
 62 }
```
Cpu0后端这两个函数的定义是一致的。因此这里假定TriCore calleesavedregister为upper context的寄存器，不需要单独处理。则函数getCallPreservedMask的定义是错误的。
getReservedRegs函数处理特殊寄存器，有特殊用途。

##### Frame寄存器
TriCoreRegisterInfo.cpp
```
146 unsigned TriCoreRegisterInfo::getFrameRegister(const MachineFunction &MF) const {
151          const TriCoreFrameLowering *TFI = getFrameLowering(MF);
152           return TFI->hasFP(MF) ? TriCore::A14 : TriCore::A10;
155 }
```
这里的getFrameLowering函数定义在TriCoreGenRegisterInfo.inc
```
const TriCoreFrameLowering *TriCoreGenRegisterInfo::
    getFrameLowering(const MachineFunction &MF) {
  return static_cast<const TriCoreFrameLowering *>(
      MF.getSubtarget().getFrameLowering());
}
```
实际上最终调用了TriCoreSubtarget的getFrameLowering函数，返回其中保存的TriCoreFrameLowering FrameLowering数据结构。
根据hasFP的返回情况，确定返回A14还是A10。A10是栈指针，如果没有专门的帧指针，直接返回栈指针，计算相对栈指针的地址。

下面的函数被PrologEpilogInserter遍调用
```
 89 void TriCoreRegisterInfo::eliminateFrameIndex(MachineBasicBlock::iterator II,
 90                 int SPAdj, unsigned FIOperandNum, RegScavenger *RS) const {
 91         MachineInstr &MI = *II;
 92         const MachineFunction &MF = *MI.getParent()->getParent();
 93         DebugLoc dl = MI.getDebugLoc();
 94         MachineBasicBlock &MBB = *MI.getParent();
 95         const MachineFrameInfo *MFI = MF.getFrameInfo();
 96         MachineOperand &FIOp = MI.getOperand(FIOperandNum);
 97         unsigned FI = FIOp.getIndex();
 98         const TargetFrameLowering *TFI = MF.getSubtarget().getFrameLowering();
 99         unsigned BasePtr = (TFI->hasFP(MF) ? TriCore::A14 : TriCore::A10);
100         // Determine if we can eliminate the index from this kind of instruction.
101         unsigned ImmOpIdx = 0;
103
104         if (MI.getOpcode() == TriCore::ADDrc) {
106                 int Offset = MFI->getObjectOffset(FI);
109                 Offset = -Offset;
112                 const TargetInstrInfo &TII = *MF.getSubtarget().getInstrInfo();
113                 MI.setDesc(TII.get(TriCore::MOVDrr));
114                 MI.getOperand(FIOperandNum).ChangeToRegister(BasePtr, false);
115
116                 if (Offset == 0)
117                         return;
118
119                 // We need to materialize the offset via add instruction.
120                 unsigned DstReg = MI.getOperand(0).getReg();
121                 if (Offset < 0) {
122                         BuildMI(MBB, std::next(II), dl, TII.get(TriCore::ADDrc), DstReg).addReg(
123                                         DstReg).addImm(Offset);
124                 } else
125                         BuildMI(MBB, std::next(II), dl, TII.get(TriCore::ADDrc), DstReg).addReg(
126                                         DstReg).addImm(-Offset);
127
128                 return;
129         }
130
132         ImmOpIdx = FIOperandNum + 1;
133
134         // FIXME: check the size of offset.
135         MachineOperand &ImmOp = MI.getOperand(ImmOpIdx);
139         int Offset = MFI->getObjectOffset(FI);
141         FIOp.ChangeToRegister(BasePtr, false);
142         ImmOp.setImm(Offset);
143 }
```
将指令由帧索引改为基址+offset访问。

TriCoreFrameLowering.h
```
class TriCoreFrameLowering : public TargetFrameLowering
  void emitPrologue(MachineFunction &MF,
                    MachineBasicBlock &MBB) const override;

  void emitEpilogue(MachineFunction &MF,
                              MachineBasicBlock &MBB) const override;

  void eliminateCallFramePseudoInstr(MachineFunction &MF,
                                     MachineBasicBlock &MBB,
                                     MachineBasicBlock::iterator I)
                                     const override;

  bool hasFP(const MachineFunction &MF) const;

  //! Stack slot size (4 bytes)
  static int stackSlotSize() { return 8; }
```
```
void TriCoreFrameLowering::emitPrologue(MachineFunction &MF,
                                    MachineBasicBlock &MBB) const {
```
```
计算栈的大小
101   uint64_t StackSize = computeStackSize(MF);
如果栈大小为0，不需要发射指令。
102   if (!StackSize) {
103     return;
104   }
如果有frame pointer
106   if (hasFP(MF)) {
107         MachineFunction::iterator I;
增加A10到A14的mov指令，作为Frame Pointer
108         BuildMI(MBB, MBBI, dl, TII.get(TriCore::MOVAAsrr), TriCore::A14)
109                                 .addReg(TriCore::A10);
110
标记每个块入口FP都Live，entry则非Live
111         // Mark the FramePtr as live-in in every block except the entry
112            for (I = std::next(MF.begin());      I != MF.end(); ++I)
113                  I->addLiveIn(TriCore::A14);
114   }

116   // Adjust the stack pointer.
117   unsigned StackReg = TriCore::A10;
下面的函数如果stacksize能够用立即数表示，则使用SUBAsc指令调整栈指针，否则使用TriCore::SUBArr。
118   unsigned OffsetReg = materializeOffset(MF, MBB, MBBI, (unsigned)StackSize);
119   if (OffsetReg) {
120     BuildMI(MBB, MBBI, dl, TII.get(TriCore::SUBArr), StackReg)
121         .addReg(StackReg)
122         .addReg(OffsetReg)
123         .setMIFlag(MachineInstr::FrameSetup);
124   } else {
125     BuildMI(MBB, MBBI, dl, TII.get(TriCore::SUBAsc))
126         .addImm(StackSize)
127         .setMIFlag(MachineInstr::FrameSetup);
128   }
```
这里每种指令的操作数和指令的定义关系如下
```
这里sub.a指令的输入是8位常量，隐含的另外一个输入是A10寄存器；没有输出，隐含为A10。仔细看这里的ins和outs。这是一个16位表示指令。这条指令没有pattern，应该不用于指令匹配。汇编指令形式sub.a sp, #126
let Defs = [A10], Uses = [A10] in
def SUBAsc : SC<0x20, (outs), (ins u8imm:$const8), "sub.a %a10, $const8", []>;

这里的sub.a指令输入为s1/s2，输出为d。是一个32位指令。汇编指令形式sub.a a3, a4, a2
def SUBArr : RR<0x01, 0x02, (outs AddrRegs:$d),
                (ins AddrRegs:$s1, AddrRegs:$s2), "sub.a $d, $s1, $s2",
                [(set AddrRegs:$d, (sub AddrRegs:$s1, AddrRegs:$s2) )]>;
```
这里在Prologue没有进行任何寄存器保存操作，相当于把upper context作为callee-saved寄存器，由硬件自动保存。那么前面的函数getCallPreservedMask实现似乎存在问题。

```
132 void TriCoreFrameLowering::emitEpilogue(MachineFunction &MF,
133                             MachineBasicBlock &MBB) const {}
```
a10 a11 a14都位于upper context，通过ret指令都会自动恢复，Epilogue为空函数，不需要任何操作。
```
135 // This function eliminates ADJCALLSTACKDOWN, ADJCALLSTACKUP pseudo
136 // instructions
137 void TriCoreFrameLowering::eliminateCallFramePseudoInstr(
138     MachineFunction &MF, MachineBasicBlock &MBB,
139     MachineBasicBlock::iterator I) const {
140   if (I->getOpcode() == TriCore::ADJCALLSTACKUP ||
141       I->getOpcode() == TriCore::ADJCALLSTACKDOWN) {
142     MBB.erase(I);
143   }
144   return;
145 }
```
这里采用直接删除对应ADJCALLSTACKDOWN, ADJCALLSTACKUP伪指令的操作。

### DAG Lowering
TriCoreISelLowering.h/cpp
SelectionDAGNodes.h
```
327 /// Represents one node in the SelectionDAG.
328 ///
329 class SDNode : public FoldingSetNode, public ilist_node<SDNode> {
330 private:
代表操作码
331   /// The operation that this node performs.
332   int16_t NodeType;
...
348 private:
349   /// Unique id per SDNode in the DAG.
350   int NodeId;
351
352   /// The values that are used by this operation.
353   SDUse *OperandList;
354
355   /// The types of the values this node defines.  SDNode's may
356   /// define multiple values simultaneously.
357   const EVT *ValueList;
358
359   /// List of uses for this SDNode.
360   SDUse *UseList;
```
ISDOpcodes.h
包含了目标无关的SelectionDAG的类型
```
/// ISD namespace - This namespace contains an enum which represents all of the
/// SelectionDAG node types and value types.
///
namespace ISD {

  //===--------------------------------------------------------------------===//
  /// ISD::NodeType enum - This enum defines the target-independent operators
  /// for a SelectionDAG.
  ///
  /// Targets may also define target-dependent operator codes for SDNodes. For
  /// example, on x86, these are the enum values in the X86ISD namespace.
  /// Targets should aim to use target-independent operators to model their
  /// instruction sets as much as possible, and only use target-dependent
  /// operators when they have special requirements.
  ///
  /// Finally, during and after selection proper, SNodes may use special
  /// operator codes that correspond directly with MachineInstr opcodes. These
  /// are used to represent selected instructions. See the isMachineOpcode()
  /// and getMachineOpcode() member functions of SDNode.
  ///
  enum NodeType {
    /// DELETED_NODE - This is an illegal value that is used to catch
    /// errors.  This opcode is not a legal opcode for any node.
    DELETED_NODE,

    /// EntryToken - This is the marker used to indicate the start of a region.
    EntryToken,
...
```
SelectionDAG/SelectionDAGDumper.cpp
```
33 std::string SDNode::getOperationName(const SelectionDAG *G)
```
这里函数包括了ISD::枚举类型对应的dump名称
#### EntryToken类型
入口节点的类型。
```
t0: ch = EntryToken
```
这里的ch代表chain类型（MVT::Other）输出。
![image](https://github.com/huizhanyi/tricore_llvm/assets/57975578/17a1fdac-c1f9-4a8a-9a0a-e2f9ca38563c)


