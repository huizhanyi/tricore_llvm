//===-- TriCoreISelLowering.cpp - TriCore DAG Lowering Implementation -----===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the TriCoreTargetLowering class.
//
//===----------------------------------------------------------------------===//

#include "TriCoreISelLowering.h"
#include "TriCore.h"
#include "TriCoreMachineFunctionInfo.h"
#include "TriCoreSubtarget.h"
#include "TriCoreTargetMachine.h"
#include "llvm/CodeGen/CallingConvLower.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineJumpTableInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/SelectionDAGISel.h"
#include "llvm/CodeGen/TargetLoweringObjectFileImpl.h"
#include "llvm/CodeGen/ValueTypes.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include "TriCoreCallingConvHook.h"

using namespace llvm;


const char *TriCoreTargetLowering::getTargetNodeName(unsigned Opcode) const {
  switch (Opcode) {
  default:
    return NULL;
  case TriCoreISD::RET_FLAG: return "RetFlag";
  case TriCoreISD::LOAD_SYM: return "LOAD_SYM";
  case TriCoreISD::MOVEi32:  return "MOVEi32";
  case TriCoreISD::CALL:     return "CALL";
  case TriCoreISD::BR_CC:    return "TriCoreISD::BR_CC";
  case TriCoreISD::Wrapper:		return "TriCoreISD::Wrapper";
  //case TriCoreISD::BR_CC_new:    return "TriCoreISD::BR_CC_new";
	//case TriCoreISD::CMP:      return "TriCoreISD::CMP";
	case TriCoreISD::CMPB:      return "TriCoreISD::CMPB";
  }
}

TriCoreTargetLowering::TriCoreTargetLowering(TriCoreTargetMachine &TriCoreTM)
    : TargetLowering(TriCoreTM), Subtarget(*TriCoreTM.getSubtargetImpl()) {
  // Set up the register classes.
  addRegisterClass(MVT::i32, &TriCore::DataRegsRegClass);
  addRegisterClass(MVT::i32, &TriCore::AddrRegsRegClass);
  addRegisterClass(MVT::i32, &TriCore::AddrRegsOthersRegClass);


  // Compute derived properties from the register classes
  computeRegisterProperties(Subtarget.getRegisterInfo());

  setStackPointerRegisterToSaveRestore(TriCore::A10);

  setSchedulingPreference(Sched::Source);

  // Nodes that require custom lowering
  setOperationAction(ISD::GlobalAddress, MVT::i32,   Custom);
  setOperationAction(ISD::BR_CC,         MVT::i32,   Custom);

}

SDValue TriCoreTargetLowering::LowerOperation(SDValue Op, SelectionDAG &DAG) const {
	switch (Op.getOpcode()) {
  default:								    llvm_unreachable("Unimplemented operand");
  case ISD::GlobalAddress:    return LowerGlobalAddress(Op, DAG);
  case ISD::BR_CC:            return LowerBR_CC(Op, DAG);
  }
}


//static StringRef printCondCode(ISD::CondCode e) {
//
//	switch(e){
//	default: return "unknown";
//	case ISD::SETEQ: return "SETEQ";
//	case ISD::SETGT: return "SETGT";
//	case ISD::SETGE: return "SETGE";
//	case ISD::SETLT: return "SETLT";
//	case ISD::SETLE: return "SETLE";
//	case ISD::SETNE: return "SETNE";
//	case ISD::SETTRUE2: return "SETTRUE2";
//	}
//}
//
//static SDValue EmitCMP(SDValue &Chain, SDValue &LHS, SDValue &RHS, SDValue &TargetCC,
//                       ISD::CondCode CC,
//                       SDLoc dl, SelectionDAG &DAG) {
//
//  TargetCC = DAG.getConstant(CC, dl, MVT::i32);
//}

SDValue TriCoreTargetLowering::LowerBR_CC(SDValue Op, SelectionDAG &DAG) const {
	SDValue Chain = Op.getOperand(0);
	ISD::CondCode CC = cast<CondCodeSDNode>(Op.getOperand(1))->get();
	SDValue LHS = Op.getOperand(2);
	SDValue RHS = Op.getOperand(3);
	SDValue Dest = Op.getOperand(4);
	SDLoc dl(Op);

	SDValue TargetCC = DAG.getConstant(CC, dl, MVT::i32);
	//Op.getOperand(1).dump();

	//SDValue Flag = EmitCMP(Chain, LHS, RHS, TargetCC, CC, dl, DAG);
	//SDValue Zero = DAG.getConstant(0, dl, MVT::i32);

	outs() << "TriCoreTargetLowering::LowerBR_CC\n";

	SDValue CompareOps[] = { Chain, TargetCC, Dest, LHS, RHS };
	EVT CompareTys[] = { MVT::Other };
	SDVTList CompareVT = DAG.getVTList(CompareTys);

	return DAG.getNode(TriCoreISD::BR_CC, dl, CompareVT, CompareOps);
//  return DAG.getNode(TriCoreISD::BR_CC, dl, Op.getValueType(),
//                     Chain, Dest, TargetCC, Flag);
}

SDValue TriCoreTargetLowering::LowerGlobalAddress(SDValue Op, SelectionDAG& DAG) const
{

	EVT VT = Op.getValueType();
  GlobalAddressSDNode *GlobalAddr = cast<GlobalAddressSDNode>(Op.getNode());
  int64_t Offset = cast<GlobalAddressSDNode>(Op)->getOffset();
  SDValue TargetAddr =
      DAG.getTargetGlobalAddress(GlobalAddr->getGlobal(), Op, MVT::i32, Offset);
  return DAG.getNode(TriCoreISD::Wrapper, Op, VT, TargetAddr);
}

//===----------------------------------------------------------------------===//
//                      Calling Convention Implementation
//===----------------------------------------------------------------------===//

#include "TriCoreGenCallingConv.inc"

//===----------------------------------------------------------------------===//
//                  Call Calling Convention Implementation
//===----------------------------------------------------------------------===//

/// TriCore call implementation
SDValue TriCoreTargetLowering::LowerCall(TargetLowering::CallLoweringInfo &CLI,
                                     SmallVectorImpl<SDValue> &InVals) const {
  SelectionDAG &DAG = CLI.DAG;
  SDLoc &Loc = CLI.DL;
  SmallVectorImpl<ISD::OutputArg> &Outs = CLI.Outs;
  SmallVectorImpl<SDValue> &OutVals = CLI.OutVals;
  SmallVectorImpl<ISD::InputArg> &Ins = CLI.Ins;
  SDValue Chain = CLI.Chain;
  SDValue Callee = CLI.Callee;
  CallingConv::ID CallConv = CLI.CallConv;
  const bool isVarArg = CLI.IsVarArg;

  CLI.IsTailCall = false;

  if (isVarArg) {
    llvm_unreachable("Unimplemented");
  }

  outs()<<"LowerCall\n";
  // Analyze operands of the call, assigning locations to each operand.
  SmallVector<CCValAssign, 16> ArgLocs;
  CCState CCInfo(CallConv, isVarArg, DAG.getMachineFunction(), ArgLocs,
                 *DAG.getContext());
  CCInfo.AnalyzeCallOperands(Outs, CC_TriCore);

  // Get the size of the outgoing arguments stack space requirement.
  const unsigned NumBytes = CCInfo.getNextStackOffset();

  Chain =
      DAG.getCALLSEQ_START(Chain, DAG.getIntPtrConstant(NumBytes, Loc, true),
                           Loc);

  SmallVector<std::pair<unsigned, SDValue>, 8> RegsToPass;
  SmallVector<SDValue, 8> MemOpChains;

  // We only support calling global addresses.
	GlobalAddressSDNode *G = dyn_cast<GlobalAddressSDNode>(Callee);
	assert(G && "We only support the calling of global addresses");
	Callee = DAG.getTargetGlobalAddress(G->getGlobal(), Loc, MVT::i32);

	int32_t originalArgPos = TCCH.findInRegRecord(G->getGlobal()->getName());
  TCCH.init();
  TCCH.setArgPos(originalArgPos);
  outs()<< "ArgPos: " << TCCH.getArgPos() <<"\n";
  // Walk the register/memloc assignments, inserting copies/loads.
  for (unsigned i = 0, e = ArgLocs.size(); i != e; ++i) {
    CCValAssign &VA = ArgLocs[i];
    SDValue Arg = OutVals[i];
    // We only handle fully promoted arguments.
    assert(VA.getLocInfo() == CCValAssign::Full && "Unhandled loc info");

    if (VA.isRegLoc()) {
    	RegsToPass.push_back(
    					std::make_pair(TCCH.getRegRecordRegister(TCCH.getArgPos()), Arg));
    	TCCH.incrArgPos();
      //RegsToPass.push_back(std::make_pair(VA.getLocReg(), Arg));
      continue;
    }
    assert(VA.isMemLoc() &&
           "Only support passing arguments through registers or via the stack");

    SDValue StackPtr = DAG.getRegister(TriCore::A10, MVT::i32);
    SDValue PtrOff = DAG.getIntPtrConstant(VA.getLocMemOffset(), Loc);
    PtrOff = DAG.getNode(ISD::ADD, Loc, MVT::i32, StackPtr, PtrOff);
    MemOpChains.push_back(DAG.getStore(Chain, Loc, Arg, PtrOff,
                                       MachinePointerInfo(), false, false, 0));
  }

  // Emit all stores, make sure they occur before the call.
  if (!MemOpChains.empty()) {
    Chain = DAG.getNode(ISD::TokenFactor, Loc, MVT::Other, MemOpChains);
  }

  // Build a sequence of copy-to-reg nodes chained together with token chain
  // and flag operands which copy the outgoing args into the appropriate regs.
  SDValue InFlag;
  for (auto &Reg : RegsToPass) {
    Chain = DAG.getCopyToReg(Chain, Loc, Reg.first, Reg.second, InFlag);
    InFlag = Chain.getValue(1);
  }



  std::vector<SDValue> Ops;
  Ops.push_back(Chain);
  Ops.push_back(Callee);

  // Add argument registers to the end of the list so that they are known live
  // into the call.
  for (auto &Reg : RegsToPass) {
    Ops.push_back(DAG.getRegister(Reg.first, Reg.second.getValueType()));
  }

  // Add a register mask operand representing the call-preserved registers.
//  const uint32_t *Mask;
//  const TargetRegisterInfo *TRI = DAG.getSubtarget().getRegisterInfo();
//  Mask = TRI->getCallPreservedMask(DAG.getMachineFunction(), CallConv);
//
//  assert(Mask && "Missing call preserved mask for calling convention");
//  Ops.push_back(DAG.getRegisterMask(Mask));

		if (InFlag.getNode()) {
			Ops.push_back(InFlag);
		}

  SDVTList NodeTys = DAG.getVTList(MVT::Other, MVT::Glue);

  // Returns a chain and a flag for retval copy to use.
  Chain = DAG.getNode(TriCoreISD::CALL, Loc, NodeTys, Ops);
  InFlag = Chain.getValue(1);

  Chain = DAG.getCALLSEQ_END(Chain, DAG.getIntPtrConstant(NumBytes, Loc, true),
                             DAG.getIntPtrConstant(0, Loc, true), InFlag, Loc);
  if (!Ins.empty()) {
    InFlag = Chain.getValue(1);
  }


  //TCCH.setArgPos(originalArgPos);
  // Handle result values, copying them out of physregs into vregs that we
  // return.
  return LowerCallResult(Chain, InFlag, CallConv, isVarArg, Ins, Loc, DAG,
                         InVals);
}

SDValue TriCoreTargetLowering::LowerCallResult(
    SDValue Chain, SDValue InGlue, CallingConv::ID CallConv, bool isVarArg,
    const SmallVectorImpl<ISD::InputArg> &Ins, SDLoc dl, SelectionDAG &DAG,
    SmallVectorImpl<SDValue> &InVals) const {
  assert(!isVarArg && "Unsupported");
  //outs()<<"LowerCallResult\n";
  // Assign locations to each value returned by this call.
  SmallVector<CCValAssign, 16> RVLocs;
  CCState CCInfo(CallConv, isVarArg, DAG.getMachineFunction(), RVLocs,
                 *DAG.getContext());

  CCInfo.AnalyzeCallResult(Ins, RetCC_TriCore);
  //DAG.getMachineFunction().getFunction()->get
  // Copy all of the result registers out of their specified physreg.
  for (auto &Loc : RVLocs) {
    Chain = DAG.getCopyFromReg(Chain, dl, Loc.getLocReg(), Loc.getValVT(),
                               InGlue).getValue(1);
    InGlue = Chain.getValue(2);
    InVals.push_back(Chain.getValue(0));
  }

  return Chain;
}

//===----------------------------------------------------------------------===//
//             Formal Arguments Calling Convention Implementation
//===----------------------------------------------------------------------===//

/// TriCore formal arguments implementation

//Called when function in entered
SDValue TriCoreTargetLowering::LowerFormalArguments(
    SDValue Chain, CallingConv::ID CallConv, bool isVarArg,
    const SmallVectorImpl<ISD::InputArg> &Ins, SDLoc dl, SelectionDAG &DAG,
    SmallVectorImpl<SDValue> &InVals) const {
  MachineFunction &MF = DAG.getMachineFunction();
  MachineRegisterInfo &RegInfo = MF.getRegInfo();

  assert(!isVarArg && "VarArg not supported");

  // Assign locations to all of the incoming arguments.
  SmallVector<CCValAssign, 16> ArgLocs;

  //get incoming arguments information
  CCState CCInfo(CallConv, isVarArg, DAG.getMachineFunction(), ArgLocs,
                 *DAG.getContext());

  StringRef funName = DAG.getMachineFunction().getFunction()->getName();

//  DAG.getMachineFunction().getFunction()
  CCInfo.AnalyzeFormalArguments(Ins, CC_TriCore);
  CCValAssign VA;
  TCCH.init();

  outs()<<"ArgLoc Size: " <<ArgLocs.size() <<"\n";
  for(uint32_t i = 0; i<ArgLocs.size(); i++) {
  	unsigned DataReg;
  	VA = ArgLocs[i];
  	if(TCCH.isRegValPtrType(MF)){
  		//Is there any address register available?
  		unsigned AddrReg = TCCH.getNextAddrRegs(funName);
  		if ( AddrReg != UNKNOWN_REG)
  			VA.convertToReg(AddrReg);
  	}
  	else
  	{
  		DataReg = TCCH.getNextDataRegs(funName);
			if ( DataReg != UNKNOWN_REG)
				VA.convertToReg(DataReg);
  	}


     if (VA.isRegLoc()) {
      // Arguments passed in registers
      EVT RegVT = VA.getLocVT();
      assert(RegVT.getSimpleVT().SimpleTy == MVT::i32 &&
             "Only support MVT::i32 register passing");

      unsigned VReg;

      outs()<<"TCCH curPos: "<<TCCH.getCurPos() <<"\n";
      // If the argument is a pointer type then create a AddrRegsClass
      // Virtual register.
      if(TCCH.isRegValPtrType(MF) ){
      	VReg =	RegInfo.createVirtualRegister(&TriCore::AddrRegsRegClass);
      	RegInfo.addLiveIn(VA.getLocReg() , VReg); //mark the register is inuse
      	TCCH.saveRegRecord(funName, VA.getLocReg(), true);
      	TCCH++;
      	//i--;
      	//continue;
      }
      // else place it inside a data register.
      else {
      	VReg = RegInfo.createVirtualRegister(&TriCore::DataRegsRegClass);
      	RegInfo.addLiveIn(DataReg, VReg); //mark the register is inuse
      	TCCH.saveRegRecord(funName, DataReg,false);
      	TCCH++;
      }

			SDValue ArgIn = DAG.getCopyFromReg(Chain, dl, VReg, RegVT);
			InVals.push_back(ArgIn);
			TCCH.incrArgPos();
      continue;
    }

    assert(VA.isMemLoc() &&
           "Can only pass arguments as either registers or via the stack");
    outs()<<"VA.isMemLoc()\n";
    const unsigned Offset = VA.getLocMemOffset();

    // create stack offset it the input argument is placed in memory
    const int FI = MF.getFrameInfo()->CreateFixedObject(4, Offset, true);
    EVT PtrTy = getPointerTy(DAG.getDataLayout());
    SDValue FIPtr = DAG.getFrameIndex(FI, PtrTy);

    assert(VA.getValVT() == MVT::i32 &&
           "Only support passing arguments as i32");

    //create a load node for the created frame object
    SDValue Load = DAG.getLoad(VA.getValVT(), dl, Chain, FIPtr,
                               MachinePointerInfo(), false, false, false, 0);

    InVals.push_back(Load);
    TCCH.incrArgPos();
  }

  TCCH.setCurPos(0);
  TCCH.printRegRecord();
//  for(int i=0; i<3; i++) {
//  	outs()<<"REg: "<<TCCH.getRegRecordRegister(i)<<"\n";
//  }


  return Chain;
}

//===----------------------------------------------------------------------===//
//               Return Value Calling Convention Implementation
//===----------------------------------------------------------------------===//

bool TriCoreTargetLowering::CanLowerReturn(
    CallingConv::ID CallConv, MachineFunction &MF, bool isVarArg,
    const SmallVectorImpl<ISD::OutputArg> &Outs, LLVMContext &Context) const {
  SmallVector<CCValAssign, 16> RVLocs;
  CCState CCInfo(CallConv, isVarArg, MF, RVLocs, Context);
  if (!CCInfo.CheckReturn(Outs, RetCC_TriCore)) {
    return false;
  }
  if (CCInfo.getNextStackOffset() != 0 && isVarArg) {
    return false;
  }
  return true;
}

SDValue
TriCoreTargetLowering::LowerReturn(SDValue Chain, CallingConv::ID CallConv,
                               bool isVarArg,
                               const SmallVectorImpl<ISD::OutputArg> &Outs,
                               const SmallVectorImpl<SDValue> &OutVals,
                               SDLoc dl, SelectionDAG &DAG) const {
  if (isVarArg) {
    report_fatal_error("VarArg not supported");
  }

  // CCValAssign - represent the assignment of
  // the return value to a location
  SmallVector<CCValAssign, 16> RVLocs;


  Type* t= DAG.getMachineFunction().getFunction()->getReturnType();
  t->dump();
  t->isPointerTy();
  // CCState - Info about the registers and stack slot.
  CCState CCInfo(CallConv, isVarArg, DAG.getMachineFunction(), RVLocs,
                 *DAG.getContext());

  CCInfo.AnalyzeReturn(Outs, RetCC_TriCore);

  SDValue Flag;
  SmallVector<SDValue, 4> RetOps(1, Chain);

  // Copy the result values into the output registers.
  for (unsigned i = 0, e = RVLocs.size(); i < e; ++i) {
    CCValAssign &VA = RVLocs[i];
    assert(VA.isRegLoc() && "Can only return in registers!");

    Chain = DAG.getCopyToReg(Chain, dl, VA.getLocReg(), OutVals[i], Flag);

    Flag = Chain.getValue(1);
    RetOps.push_back(DAG.getRegister(VA.getLocReg(), VA.getLocVT()));
  }

  RetOps[0] = Chain; // Update chain.

  // Add the flag if we have it.
  if (Flag.getNode()) {
    RetOps.push_back(Flag);
  }

  return DAG.getNode(TriCoreISD::RET_FLAG, dl, MVT::Other, RetOps);
}