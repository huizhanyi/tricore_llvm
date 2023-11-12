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
这里图形表示中包括了节点的id类型EntryToken，唯一id号和chain输出类型。
#### Constant类型
页节点类型，表示一个常数，例如

![image](https://github.com/huizhanyi/tricore_llvm/assets/57975578/45111af4-84fe-4258-be27-622d6ee95c53)
输出一个常数4
```
SelectionDAGNodes.h
1494 class ConstantSDNode : public SDNode {
1495   const ConstantInt *Value;
1496   friend class SelectionDAG;
1497   ConstantSDNode(bool isTarget, bool isOpaque, const ConstantInt *val,
1498                  DebugLoc DL, EVT VT)
1499     : SDNode(isTarget ? ISD::TargetConstant : ISD::Constant,
1500              0, DL, getSDVTList(VT)), Value(val) {
1501     SubclassData |= (uint16_t)isOpaque;
1502   }
1503 public:
1504
1505   const ConstantInt *getConstantIntValue() const { return Value; }
1506   const APInt &getAPIntValue() const { return Value->getValue(); }
1507   uint64_t getZExtValue() const { return Value->getZExtValue(); }
1508   int64_t getSExtValue() const { return Value->getSExtValue(); }
1509
1510   bool isOne() const { return Value->isOne(); }
1511   bool isNullValue() const { return Value->isNullValue(); }
1512   bool isAllOnesValue() const { return Value->isAllOnesValue(); }
1513
1514   bool isOpaque() const { return SubclassData & 1; }
1515
1516   static bool classof(const SDNode *N) {
1517     return N->getOpcode() == ISD::Constant ||
1518            N->getOpcode() == ISD::TargetConstant;
1519   }
1520 };
```
#### FrameIndex类型
代表一个帧索引，例如

![image](https://github.com/huizhanyi/tricore_llvm/assets/57975578/71cee821-0bd3-4587-b1cf-272087a7d7e8)
这里代表帧索引为0，输出i32类型，似乎是一个地址。
```
SelectionDAGNodes.h
1595 class FrameIndexSDNode : public SDNode {
1596   int FI;
1597   friend class SelectionDAG;
1598   FrameIndexSDNode(int fi, EVT VT, bool isTarg)
1599     : SDNode(isTarg ? ISD::TargetFrameIndex : ISD::FrameIndex,
1600       0, DebugLoc(), getSDVTList(VT)), FI(fi) {
1601   }
1602 public:
1603
1604   int getIndex() const { return FI; }
1605
1606   static bool classof(const SDNode *N) {
1607     return N->getOpcode() == ISD::FrameIndex ||
1608            N->getOpcode() == ISD::TargetFrameIndex;
1609   }
1610 };
```
#### 其他介绍
参考：
LLVM 之后端篇（4）：理解指令选择的 dump 输出
https://csstormq.github.io/blog/LLVM%20%E4%B9%8B%E5%90%8E%E7%AB%AF%E7%AF%87%EF%BC%884%EF%BC%89%EF%BC%9A%E7%90%86%E8%A7%A3%E6%8C%87%E4%BB%A4%E9%80%89%E6%8B%A9%E7%9A%84%20dump%20%E8%BE%93%E5%87%BA

#### 第一个 LLVM IR -> SelectionDAG pass
对应的上述所有操作（下图）都位于遍TriCoreDAGToDAGISel,参考
![image](https://github.com/huizhanyi/tricore_llvm/assets/57975578/a46c7a1c-8366-4e73-bbd6-dfb7b059ae8d)

https://csstormq.github.io/blog/LLVM%20%E4%B9%8B%E5%90%8E%E7%AB%AF%E7%AF%87%EF%BC%884%EF%BC%89%EF%BC%9A%E7%90%86%E8%A7%A3%E6%8C%87%E4%BB%A4%E9%80%89%E6%8B%A9%E7%9A%84%20dump%20%E8%BE%93%E5%87%BA

TriCoreTargetLowering在SubTarget初始化时生成,而TriCoreDAGToDAGISel包含了TriCoreSubtarget
```
89 class TriCoreDAGToDAGISel : public SelectionDAGISel {
90         const TriCoreSubtarget &Subtarget;
```
```
43 class SelectionDAGISel : public MachineFunctionPass {
遍的入口方法，该方法完成了所有的该遍任务
68   bool runOnMachineFunction(MachineFunction &MF) override;
```
SelectionDAGISel.cpp
```
 415 bool SelectionDAGISel::runOnMachineFunction(MachineFunction &mf) {
```
#### TriCoreTargetLowering
TriCoreISelLowering.h
TriCore定制的Selection DAG类型
```
28 namespace TriCoreISD {
29 enum NodeType {
30   // Start the numbering where the builtin ops and target ops leave off.
31   FIRST_NUMBER = ISD::BUILTIN_OP_END,
32   RET_FLAG,
33   // This loads the symbol (e.g. global address) into a register.
34   LOAD_SYM,
35   // This loads a 32-bit immediate into a register.
36   MOVEi32,
37   CALL,
38         // TriCore has a different way of lowering branch conditions.
39         BR_CC,
40         // This loads the comparison type, as Tricore doesn't support all
41         // sorts of comparisons, some have to be created.
42         CMP,
43         // This load the addressing information
44         Wrapper,
45         // This loads the Shift instructions operands. Right and left shift
46         // depends on the signed-ness on the shift value. A negytive value is
47         // a right shift, and vice versa.
48         SH,
49         // Arthimatic Shift
50         SHA,
51         // Loads ternary operators
52         SELECT_CC,
53         LOGICCMP,
54         IMASK,
55         EXTR
56         };
57 }
```
重载父类一系列虚函数
```
 62 class TriCoreTargetLowering : public TargetLowering {
 63 public:
 64   explicit TriCoreTargetLowering(TriCoreTargetMachine &TM);
 65
 66   /// LowerOperation - Provide custom lowering hooks for some operations.
 67   virtual SDValue LowerOperation(SDValue Op, SelectionDAG &DAG) const;
 68
 69   /// getTargetNodeName - This method returns the name of a target specific
 70   //  DAG node.
 71   virtual const char *getTargetNodeName(unsigned Opcode) const;
```
TriCoreISelLowering.cpp
```
103 SDValue TriCoreTargetLowering::LowerOperation(SDValue Op, SelectionDAG &DAG) const {
104         switch (Op.getOpcode()) {
105   default:                                                                  llvm_unreachable("Unimplemented operand");
106   case ISD::GlobalAddress:      return LowerGlobalAddress(Op, DAG);
107   case ISD::BR_CC:              return LowerBR_CC(Op, DAG);
108   case ISD::SELECT_CC:          return LowerSELECT_CC(Op, DAG);
109   case ISD::SETCC:              return LowerSETCC(Op, DAG);
110   case ISD::SHL:
111   case ISD::SRL:
112   case ISD::SRA:                return LowerShifts(Op, DAG);
113   //case ISD::SIGN_EXTEND:              return LowerSIGN_EXTEND(Op, DAG);
114   //case ISD::SIGN_EXTEND_INREG:  return LowerSIGN_EXTEND_INREG(Op, DAG);
115   }
116 }
```
需要特殊处理的操作入口函数，看外部的代码，LowerOperation主要在合法化阶段调用？
检查一下LowerGlobalAddress的实现
```
366 SDValue TriCoreTargetLowering::LowerGlobalAddress(SDValue Op, SelectionDAG& DAG) const
367 {
368
返回Op代表的操作结果操作数的值类型
369   EVT VT = Op.getValueType();
370
返回Op代表的操作（GlobalAddressSDNode）的节点
371         GlobalAddressSDNode *GlobalAddr = cast<GlobalAddressSDNode>(Op.getNode());
返回offset值
372         int64_t Offset = cast<GlobalAddressSDNode>(Op)->getOffset();
取到目标地址，这是一个SDValue
373         SDValue TargetAddr =
374                  DAG.getTargetGlobalAddress(GlobalAddr->getGlobal(), Op, MVT::i32, Offset);
返回一个TriCoreISD::Wrapper类型节点
375         return DAG.getNode(TriCoreISD::Wrapper, Op, VT, TargetAddr);
376
377 }
```
再看看shift操作
```
110   case ISD::SHL:
111   case ISD::SRL:
112   case ISD::SRA:                return LowerShifts(Op, DAG);
```
```
118 SDValue TriCoreTargetLowering::LowerShifts(SDValue Op,
119                 SelectionDAG &DAG) const {
Op对应的Node的操作码
120         unsigned Opc = Op.getOpcode();
Op对应的Node
121         SDNode* N = Op.getNode();
取shift值，这里对应1号操作数，0号应该是被迁移的操作数
122         SDValue shiftValue =  N->getOperand(1);
123
Op的值类型
124         EVT VT = Op.getValueType();
125         SDLoc dl(N);
127         switch (Opc) {
129         case ISD::SHL:
直接替换为TriCoreISD::SH，这里操作数、类型等都不变
130                 return DAG.getNode(TriCoreISD::SH, dl, VT, N->getOperand(0), N->getOperand(1));

131         case ISD::SRL:
132         case ISD::SRA:
133                 if(isa<ConstantSDNode>(shiftValue)) {
shift值为常数
134                         //outs() <<"shift constant\n";
取shift常量值
135                         int64_t shiftSVal = cast<ConstantSDNode>(shiftValue)->getSExtValue();

136                         assert((shiftSVal>=-32 && shiftSVal<32) &&
137                                                         "Shift can only be between -32 and +31");
取shift SD节点
138                         ConstantSDNode *shiftSD = cast<ConstantSDNode>(N->getOperand(1));
对shift值取反
139                         uint64_t shiftVal = -shiftSD->getZExtValue();
生成一个新的constant SD节点
140                         SDValue negShift = DAG.getConstant(shiftVal, dl, MVT::i32);
141
如果是ISD::SRL，则使用TriCore的SH操作，否则使用SHA操作
142                         unsigned Opcode = (Opc== ISD::SRL) ? TriCoreISD::SH : TriCoreISD::SHA;
143
生成新的SDNode，返回SDValue
144                         return DAG.getNode(Opcode, dl, VT, N->getOperand(0), negShift);
145                 }
...
155         }
```
处理ISD::BR_CC类型
```
/// BR_CC - Conditional branch.  The behavior is like that of SELECT_CC, in
/// that the condition is represented as condition code, and two nodes to
/// compare, rather than as a combined SetCC node.  The operands in order
/// are chain, cc, lhs, rhs, block to branch to if condition is true.
BR_CC,
```

```
314 SDValue TriCoreTargetLowering::LowerBR_CC(SDValue Op, SelectionDAG &DAG) const {
对应节点的操作数0
315   SDValue Chain = Op.getOperand(0);
对应节点的操作数1，为条件节点，取条件码
316   ISD::CondCode CC = cast<CondCodeSDNode>(Op.getOperand(1))->get();
左操作数
317   SDValue LHS   = Op.getOperand(2);
右操作数
318   SDValue RHS   = Op.getOperand(3);
目标块
319   SDValue Dest  = Op.getOperand(4);
320   SDLoc dl  (Op);
321
322   SDValue tricoreCC;
323   SDValue Flag = EmitCMP(LHS, RHS, CC, dl, DAG, tricoreCC);
324
325   //Flag.getValue(1).dump();
326
替换为TriCore具体的ISD操作
327   return DAG.getNode(TriCoreISD::BR_CC, dl, Op.getValueType(),
328                        Chain, Dest, Flag.getValue(0), tricoreCC, Flag.getValue(1));
329
330 }
```
从这里看，有一系列TriCore具体的ISD类型被插入到DAG中。

```
348 SDValue TriCoreTargetLowering::LowerSELECT_CC(SDValue Op,
349                                              SelectionDAG &DAG) const {
350   SDValue LHS    = Op.getOperand(0);
351   SDValue RHS    = Op.getOperand(1);
352   SDValue TrueV  = Op.getOperand(2);
353   SDValue FalseV = Op.getOperand(3);
354   ISD::CondCode CC = cast<CondCodeSDNode>(Op.getOperand(4))->get();
355   SDLoc dl   (Op);
356
357   SDValue tricoreCC;
358   SDValue Flag = EmitCMP(LHS, RHS, CC, dl, DAG, tricoreCC);
359
360   SDVTList VTs = DAG.getVTList(Op.getValueType(), MVT::Glue);
361   SDValue Ops[] = {TrueV, FalseV, tricoreCC, Flag};
362
363   return DAG.getNode(TriCoreISD::SELECT_CC, dl, VTs, Ops);
364 }
```
使用如下命令研究节点替换的时机：
llc -debug-only=isel -march=tricore -relocation-model=pic -filetype=asm test1.ll -o test.s
可以看到Legalized selection DAG阶段完成了对ISD::SELECT_CC的替换，替换为TriCoreISD::CMP和TriCoreISD::SELECT_CC
经过指令选择阶段后进一步被替换为TriCore支持的指令。如下所示
```
        0x56032b845a90: <multiple use>
        0x56032b845bc0: i32 = Constant<0> [ID=-3]

        0x56032b845f50: i32 = Constant<-3> [ID=-3]

        0x56032b846080: i32 = Constant<-2> [ID=-3]

        0x56032b845cf0: ch = seteq [ID=-3]

      0x56032b8467a0: i32 = select_cc 0x56032b845a90, 0x56032b845bc0, 0x56032b845f50, 0x56032b846080, 0x56032b845cf0 [ORD=3] [ID=-3]
```
转换到
```
        0x56032b845f50: i32 = Constant<-3> [ID=4]

        0x56032b846080: i32 = Constant<-2> [ID=5]

        0x56032b845e20: i32 = Constant<1>

          0x56032b845a90: <multiple use>
          0x56032b845bc0: <multiple use>
          0x56032b845bc0: <multiple use>
        0x56032b8461b0: i32,glue = TriCoreISD::CMP 0x56032b845a90, 0x56032b845bc0, 0x56032b845bc0 [ORD=3]

      0x56032b848090: i32,glue = TriCoreISD::SELECT_CC 0x56032b845f50, 0x56032b846080, 0x56032b845e20, 0x56032b8461b0 [ORD=3]
```
转换到
```
          0x56032b845a90: <multiple use>
          0x56032b845e20: <multiple use>
        0x56032b8461b0: i32,glue = EQrc 0x56032b845a90, 0x56032b845e20 [ORD=3]

      0x56032b848090: i32 = Select8 0x56032b8482f0, 0x56032b8481c0, 0x56032b845cf0, 0x56032b8461b0 [ORD=3]
```
```
  /// This method should be implemented by targets that mark instructions with
  /// the 'usesCustomInserter' flag.  These instructions are special in various
  /// ways, which require special support to insert.  The specified MachineInstr
  /// is created but not inserted into any basic blocks, and this method is
  /// called to expand it into a sequence of instructions, potentially also
  /// creating new basic blocks and control flow.
  /// As long as the returned basic block is different (i.e., we created a new
  /// one), the custom inserter is free to modify the rest of \p MBB.
  virtual MachineBasicBlock *
    EmitInstrWithCustomInserter(MachineInstr *MI, MachineBasicBlock *MBB) const;
```
Select8用到了usesCustomInserter=1
```
let usesCustomInserter = 1 in {
  def Select8  : Pseudo<(outs DataRegs:$dst),
                (ins DataRegs:$src, DataRegs:$src2, i32imm:$cc, DataRegs:$src1 ),
                 "# Select8 PSEUDO",
                 [(set DataRegs:$dst, (TriCoreselectcc DataRegs:$src, DataRegs:$src2, imm:$cc, DataRegs:$src1))]>;
}
```
```
380 MachineBasicBlock*
381 TriCoreTargetLowering::EmitInstrWithCustomInserter(MachineInstr *MI,
382                                                   MachineBasicBlock *BB) const {
取指令操作码
383   unsigned Opc = MI->getOpcode();
384
取TargetInstrInfo
385   const TargetInstrInfo &TII = *BB->getParent()->getSubtarget().getInstrInfo();
取调试信息
386   DebugLoc dl = MI->getDebugLoc();
387
处理TriCore::Select8指令类型，这里只需要处理这种指令类型。ISD类型TriCoreselectcc生成了Select8指令。Instruction selection结束就会生成Select8类型指令
388   assert(Opc == TriCore::Select8 && "Unexpected instr type to insert");
389   // To "insert" a SELECT instruction, we actually have to insert the diamond
390   // control-flow pattern.  The incoming instruction knows the destination vreg
391   // to set, the condition code register to branch on, the true/false values to
392   // select between, and a branch opcode to use.
393   const BasicBlock *LLVM_BB = BB->getBasicBlock();
394   MachineFunction::iterator I = BB;
395   ++I;
396
397   //  thisMBB:
398   //  ...
399   //   TrueVal = ...
400   //   cmpTY ccX, r1, r2
401   //   jCC copy1MBB
402   //   fallthrough --> copy0MBB
403   MachineBasicBlock *thisMBB = BB;
404   MachineFunction *F = BB->getParent();
405   MachineBasicBlock *copy0MBB = F->CreateMachineBasicBlock(LLVM_BB);
406   MachineBasicBlock *copy1MBB = F->CreateMachineBasicBlock(LLVM_BB);
407   F->insert(I, copy0MBB);
408   F->insert(I, copy1MBB);
409   // Update machine-CFG edges by transferring all successors of the current
410   // block to the new block which will contain the Phi node for the select.
411   copy1MBB->splice(copy1MBB->begin(), BB,
412                    std::next(MachineBasicBlock::iterator(MI)), BB->end());
413   copy1MBB->transferSuccessorsAndUpdatePHIs(BB);
414   // Next, add the true and fallthrough blocks as its successors.
415   BB->addSuccessor(copy0MBB);
416   BB->addSuccessor(copy1MBB);
417
418   //MI->dump();
419
420   BuildMI(BB, dl, TII.get(TriCore::JNZsbr))
421     .addMBB(copy1MBB)
422         .addReg(MI->getOperand(4).getReg());
423
424   //  copy0MBB:
425   //   %FalseValue = ...
426   //   # fallthrough to copy1MBB
427   BB = copy0MBB;
428
429   // Update machine-CFG edges
430   BB->addSuccessor(copy1MBB);
431
432   //  copy1MBB:
433   //   %Result = phi [ %FalseValue, copy0MBB ], [ %TrueValue, thisMBB ]
434   //  ...
435   BB = copy1MBB;
436   BuildMI(*BB, BB->begin(), dl, TII.get(TriCore::PHI),
437           MI->getOperand(0).getReg())
438     .addReg(MI->getOperand(2).getReg()).addMBB(copy0MBB)
439     .addReg(MI->getOperand(1).getReg()).addMBB(thisMBB);
440
完成处理后，Select8指令即被删除，因此这个函数应该是在比较后面的遍里调用的？
使用-print-before-all和-print-after-all，可以看到 Expand ISel Pseudo-instructions遍之前存在Select8指令，之后
则不存在，因此应该是在该遍调用的。确认ExpandISelPseudos.cpp:ExpandISelPseudos::runOnMachineFunction调用了该函数
441   MI->eraseFromParent();   // The pseudo instruction is gone now.
442   return BB;
443 }
```
