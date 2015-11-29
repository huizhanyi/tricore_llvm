//===-- TriCoreISelDAGToDAG.cpp - A dag to dag inst selector for TriCore --===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines an instruction selector for the TriCore target.
//
//===----------------------------------------------------------------------===//

#include "TriCore.h"
#include "TriCoreTargetMachine.h"
#include "llvm/CodeGen/SelectionDAGISel.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

#include "TriCoreInstrInfo.h"

#define DEBUG_TYPE "tricore-isel"

using namespace llvm;



namespace {
  struct TriCoreISelAddressMode {
    enum {
      RegBase,
      FrameIndexBase
    } BaseType;

    struct {            // This is really a union, discriminated by BaseType!
      SDValue Reg;
      int FrameIndex;
    } Base;

    int64_t Disp;
    const GlobalValue *GV;
    const Constant *CP;
    const BlockAddress *BlockAddr;
    const char *ES;
    int JT;
    unsigned Align;    // CP alignment.

    TriCoreISelAddressMode()
      : BaseType(RegBase), Disp(0), GV(nullptr), CP(nullptr),
        BlockAddr(nullptr), ES(nullptr), JT(-1), Align(0) {
    }

    bool hasSymbolicDisplacement() const {
      return GV != nullptr || CP != nullptr || ES != nullptr || JT != -1;
    }

    void dump() {
      errs() << "rriCoreISelAddressMode " << this << '\n';
      if (BaseType == RegBase && Base.Reg.getNode() != nullptr) {
        errs() << "Base.Reg ";
        Base.Reg.getNode()->dump();
      } else if (BaseType == FrameIndexBase) {
        errs() << " Base.FrameIndex " << Base.FrameIndex << '\n';
      }
      errs() << " Disp " << Disp << '\n';
      if (GV) {
        errs() << "GV ";
        GV->dump();
      } else if (CP) {
        errs() << " CP ";
        CP->dump();
        errs() << " Align" << Align << '\n';
      } else if (ES) {
        errs() << "ES ";
        errs() << ES << '\n';
      } else if (JT != -1)
        errs() << " JT" << JT << " Align" << Align << '\n';
    }
  };
}

/// TriCoreDAGToDAGISel - TriCore specific code to select TriCore machine
/// instructions for SelectionDAG operations.
///
namespace {
class TriCoreDAGToDAGISel : public SelectionDAGISel {
  const TriCoreSubtarget &Subtarget;

public:
  explicit TriCoreDAGToDAGISel(TriCoreTargetMachine &TM, CodeGenOpt::Level OptLevel)
      : SelectionDAGISel(TM, OptLevel), Subtarget(*TM.getSubtargetImpl()) {}

  SDNode *Select(SDNode *N);

  bool SelectAddr(SDValue Addr, SDValue &Base, SDValue &Offset);
  bool SelectAddr_new(SDValue N, SDValue &Base, SDValue &Disp);
  bool MatchAddress(SDValue N, TriCoreISelAddressMode &AM);
  bool MatchWrapper(SDValue N, TriCoreISelAddressMode &AM);
	bool MatchAddressBase(SDValue N, TriCoreISelAddressMode &AM);

  virtual const char *getPassName() const {
    return "TriCore DAG->DAG Pattern Instruction Selection";
  }

private:
  SDNode *SelectMoveImmediate(SDNode *N);
  SDNode *SelectConditionalBranch(SDNode *N,uint64_t code);
  SDNode *SelectBRCC(SDNode* N);

// Include the pieces autogenerated from the target description.
#include "TriCoreGenDAGISel.inc"
};
} // end anonymous namespace

/// MatchWrapper - Try to match MSP430ISD::Wrapper node into an addressing mode.
/// These wrap things that will resolve down into a symbol reference.  If no
/// match is possible, this returns true, otherwise it returns false.
bool TriCoreDAGToDAGISel::MatchWrapper(SDValue N, TriCoreISelAddressMode &AM) {
  // If the addressing mode already has a symbol as the displacement, we can
  // never match another symbol.
  if (AM.hasSymbolicDisplacement()) {
  	DEBUG(errs().changeColor(raw_ostream::YELLOW,1);
  	errs() <<"hasSymbolicDisplacement\n";
  	N.dump();
  	errs().changeColor(raw_ostream::WHITE,0); );
  	return true;
  }

  SDValue N0 = N.getOperand(0);
  DEBUG(errs() << "Match Wrapper N => ";
  N.dump();
  errs()<< "N0 => "; N0.dump(); );


  if (GlobalAddressSDNode *G = dyn_cast<GlobalAddressSDNode>(N0)) {
    AM.GV = G->getGlobal();
    AM.Disp += G->getOffset();
    DEBUG(errs() << "MatchWrapper->Displacement: " << AM.Disp );
    //AM.SymbolFlags = G->getTargetFlags();
  }
  return false;
}

/// MatchAddressBase - Helper for MatchAddress. Add the specified node to the
/// specified addressing mode without any further recursion.
bool TriCoreDAGToDAGISel::MatchAddressBase(SDValue N, TriCoreISelAddressMode &AM) {
  // Is the base register already occupied?
  if (AM.BaseType != TriCoreISelAddressMode::RegBase || AM.Base.Reg.getNode()) {
    // If so, we cannot select it.
    return true;
  }

  // Default, generate it as a register.
  AM.BaseType = TriCoreISelAddressMode::RegBase;
  AM.Base.Reg = N;
  return false;
}


bool TriCoreDAGToDAGISel::MatchAddress(SDValue N, TriCoreISelAddressMode &AM) {
  DEBUG(errs() << "MatchAddress: "; AM.dump());
  DEBUG(errs() << "Node: "; N.dump());


  switch (N.getOpcode()) {
  default: break;
  case ISD::Constant: {

    uint64_t Val = cast<ConstantSDNode>(N)->getSExtValue();
    AM.Disp += Val;
    DEBUG(errs() << "MatchAddress->Disp: " << AM.Disp ;);
    return false;
  }

  case TriCoreISD::Wrapper:
    if (!MatchWrapper(N, AM))
      return false;
    break;

  case ISD::FrameIndex:
    if (AM.BaseType == TriCoreISelAddressMode::RegBase
        && AM.Base.Reg.getNode() == nullptr) {
      AM.BaseType = TriCoreISelAddressMode::FrameIndexBase;
      AM.Base.FrameIndex = cast<FrameIndexSDNode>(N)->getIndex();
      return false;
    }
    break;

  case ISD::ADD: {
  	TriCoreISelAddressMode Backup = AM;
    if (!MatchAddress(N.getNode()->getOperand(0), AM) &&
        !MatchAddress(N.getNode()->getOperand(1), AM))
      return false;
    AM = Backup;
    if (!MatchAddress(N.getNode()->getOperand(1), AM) &&
        !MatchAddress(N.getNode()->getOperand(0), AM))
      return false;
    AM = Backup;

    break;
  }

  case ISD::OR:
    // Handle "X | C" as "X + C" iff X is known to have C bits clear.
    if (ConstantSDNode *CN = dyn_cast<ConstantSDNode>(N.getOperand(1))) {
    	TriCoreISelAddressMode Backup = AM;
      uint64_t Offset = CN->getSExtValue();
      // Start with the LHS as an addr mode.
      if (!MatchAddress(N.getOperand(0), AM) &&
          // Address could not have picked a GV address for the displacement.
          AM.GV == nullptr &&
          // Check to see if the LHS & C is zero.
          CurDAG->MaskedValueIsZero(N.getOperand(0), CN->getAPIntValue())) {
        AM.Disp += Offset;
        return false;
      }
      AM = Backup;
    }
    break;
  }

  return MatchAddressBase(N, AM);
}

/// SelectAddr - returns true if it is able pattern match an addressing mode.
/// It returns the operands which make up the maximal addressing mode it can
/// match by reference.
bool TriCoreDAGToDAGISel::SelectAddr_new(SDValue N,
                                    SDValue &Base, SDValue &Disp) {
	TriCoreISelAddressMode AM;

	DEBUG( errs().changeColor(raw_ostream::YELLOW,1);
	N.dump();
	errs().changeColor(raw_ostream::WHITE,0) );


  if (MatchAddress(N, AM))
    return false;

  EVT VT = N.getValueType();
  if (AM.BaseType == TriCoreISelAddressMode::RegBase) {
  	DEBUG(errs() << "It's a reg base";);
    if (!AM.Base.Reg.getNode())
      AM.Base.Reg = CurDAG->getRegister(0, VT);
  }


  Base = (AM.BaseType == TriCoreISelAddressMode::FrameIndexBase)
             ? CurDAG->getTargetFrameIndex(
                   AM.Base.FrameIndex,
                   getTargetLowering()->getPointerTy(CurDAG->getDataLayout()))
             : AM.Base.Reg;

  if (AM.GV) {
  	DEBUG(errs() <<"AM.GV" );
  	//GlobalAddressSDNode *gAdd = dyn_cast<GlobalAddressSDNode>(N.getOperand(0));
  	Base = N;
  	Disp = CurDAG->getTargetConstant(AM.Disp, N, MVT::i32);
  }
  else {
  	 DEBUG(errs()<<"SelectAddr -> AM.Disp\n";
  	 errs()<< "SelectAddr -> Displacement: " << AM.Disp; );
  	Disp = CurDAG->getTargetConstant(AM.Disp, SDLoc(N), MVT::i32);
  }


  return true;
}


bool TriCoreDAGToDAGISel::SelectAddr(SDValue Addr, SDValue &Base, SDValue &Offset) {


	return SelectAddr_new(Addr, Base, Offset);

	outs().changeColor(raw_ostream::GREEN,1);
	Addr.dump();
	outs() <<"Addr Opcode: " << Addr.getOpcode() <<"\n";
	outs().changeColor(raw_ostream::WHITE,0);


	if (FrameIndexSDNode *FIN = dyn_cast<FrameIndexSDNode>(Addr)) {
//    EVT PtrVT = getTargetLowering()->getPointerTy(*TM.getDataLayout());
    EVT PtrVT = getTargetLowering()->getPointerTy(CurDAG->getDataLayout());
    Base = CurDAG->getTargetFrameIndex(FIN->getIndex(), PtrVT);
    Offset = CurDAG->getTargetConstant(0, Addr, MVT::i32);
//    outs().changeColor(raw_ostream::RED)<<"Selecting Frame!\n";
//    outs().changeColor(raw_ostream::WHITE);

    return true;
  }

	SDValue Addr0 = Addr.getOperand(0);
	if(GlobalAddressSDNode *gAdd = dyn_cast<GlobalAddressSDNode>(Addr0)) {
		outs()<<"This is working!!!!!!!!!!!!!!\n";
		Base = Addr;
		Offset = CurDAG->getTargetConstant(gAdd->getOffset(), Addr, MVT::i32);
		return true;
	}

//	SDValue N0 = Addr.getOperand(0);
//	if (GlobalAddressSDNode *G = dyn_cast<GlobalAddressSDNode>(N0)) {
//		EVT VT = Addr.getValueType();
//		Base = CurDAG->getRegister(0, VT);
//			//Base = G->getGlobal();
//	   // Offset += G->getOffset();
//	   // outs()<< "Displacement: " << Offset << "\n";
//
//	    Offset = CurDAG->getTargetGlobalAddress(G->getGlobal(), SDLoc(Addr),
//	  				MVT::i32, 4,
//					0/*AM.SymbolFlags*/);
//	  	//Disp.dump();
//
//	  	GlobalAddressSDNode* GG = cast<GlobalAddressSDNode>(Offset);
//	  	outs() << "Offset: " << GG->getOffset() << "\n";
//	    return true;
//	    //AM.SymbolFlags = G->getTargetFlags();
//	  }

  if (Addr.getOpcode() == ISD::TargetExternalSymbol ||
      Addr.getOpcode() == ISD::TargetGlobalAddress ||
      Addr.getOpcode() == ISD::TargetGlobalTLSAddress) {

  	outs().changeColor(raw_ostream::BLUE,1);
		Addr.dump();
		outs().changeColor(raw_ostream::WHITE,0);

    return false; // direct calls.
  }

  Base = Addr;
  Offset = CurDAG->getTargetConstant(0, Addr, MVT::i32);
  return true;
}

SDNode *TriCoreDAGToDAGISel::SelectMoveImmediate(SDNode *N) {
  // Make sure the immediate size is supported.
  ConstantSDNode *ConstVal = cast<ConstantSDNode>(N);
  int64_t ImmSExt = ConstVal->getSExtValue();
  int64_t ImmZExt = ConstVal->getZExtValue();
  DEBUG(errs() <<"ImmSExt: "<<  ImmSExt; );
  DEBUG(errs() <<"ImmZExt: "<<  ImmZExt; );
  DEBUG(errs().changeColor(raw_ostream::BLUE,1) << "Is this 16SExt?: "
    		<< isInt<16>(ImmSExt) << "\n" << "Is this 16ZExt?: "
				<< isUInt<16>(ImmZExt) << "\n"; );

  outs().changeColor(raw_ostream::WHITE,0);

  // Select the low part of the immediate move.
  uint64_t LoMask = 0xffff;
  uint64_t ImmLo = (ImmZExt & LoMask);


  if (isInt<16>(ImmSExt)) {
  	SDValue ImmValNode = CurDAG->getTargetConstant(ImmSExt, N, MVT::i32);
  	return CurDAG->getMachineNode(TriCore::MOVrlc, N, MVT::i32, ImmValNode);
  }

  if(isUInt<16>(ImmZExt) && ImmLo) {
  	SDValue ImmValNode = CurDAG->getTargetConstant(ImmZExt, N, MVT::i32);
  	return	CurDAG->getMachineNode(TriCore::MOVUrlc, N, MVT::i32, ImmValNode); //MOVLOi16
  }

  SDValue ImmValNode = CurDAG->getTargetConstant(ImmZExt, N, MVT::i32);
  return CurDAG->getMachineNode(TriCore::MOVi32, N, MVT::i32, ImmValNode);

 }

static StringRef printCondCode(ISD::CondCode e) {

	switch(e){
	default: return "unknown";
	case ISD::SETEQ: return "SETEQ";
	case ISD::SETGT: return "SETGT";
	case ISD::SETGE: return "SETGE";
	case ISD::SETLT: return "SETLT";
	case ISD::SETLE: return "SETLE";
	case ISD::SETNE: return "SETNE";
	case ISD::SETTRUE2: return "SETTRUE2";
	}
}


SDNode *TriCoreDAGToDAGISel::SelectConditionalBranch(SDNode *N, uint64_t code) {

//	SDValue Chain = N->getOperand(0);
	SDValue Cond = N->getOperand(1);
	SDValue LHS = N->getOperand(3);
	SDValue RHS = N->getOperand(4);
	SDValue Target = N->getOperand(2);

	uint64_t realCond;
	unsigned opCode;
	bool isSExt4= false;
	ConstantSDNode *Ccode= cast<ConstantSDNode>(Cond);
	uint64_t CVal = Ccode->getZExtValue();

	if (const ConstantSDNode *RHSConst = dyn_cast<ConstantSDNode>(RHS) ){
		outs() <<"Value of RHS: " << RHSConst->getSExtValue() <<"\n";
		isSExt4 = (isInt<4>(RHSConst->getSExtValue())) ? true:false;
		if(isSExt4)
			RHS = CurDAG->getTargetConstant(RHSConst->getSExtValue(), N, MVT::i32);
	}

	switch(CVal) {

		case ISD::SETLT:
				realCond=ISD::SETLT;
				opCode = (isSExt4==true) ? TriCore::JLTbrc : TriCore::JLTbrr;
				break;
		case ISD::SETGE:
				realCond=ISD::SETGE;
				opCode = (isSExt4==true) ? TriCore::JGEbrc : TriCore::JGEbrr;
				break;
		case ISD::SETGT:
				std::swap(LHS,RHS);
				realCond=ISD::SETLT;
				opCode = TriCore::JLTbrr;
				break;
		case ISD::SETLE:
				std::swap(LHS,RHS);
				realCond=ISD::SETGE;
				opCode = TriCore::JGEbrr;
				break;
		case ISD::SETEQ:
				realCond=ISD::SETEQ;
				opCode = TriCore::JEQbrr;
				break;
		case ISD::SETNE:
				realCond=ISD::SETNE;
				opCode = TriCore::JNEbrr;
				break;


	}


	outs().changeColor(raw_ostream::BLUE,1);
	Cond.dump();
	LHS.dump();
	RHS.dump();
	outs().changeColor(raw_ostream::WHITE,0);


	outs()<<"Generate a branch instruction.\n";
	//ISD::CondCode CC = cast<CondCodeSDNode>(N->getOperand(1))->get();
//	outs().changeColor(raw_ostream::GREEN,1)<<printCondCode(CC) <<"\n";
	outs().changeColor(raw_ostream::WHITE,0);
	SDValue CCVal = CurDAG->getTargetConstant(realCond, N, MVT::i32);
//	CCVal.dump();
	SDValue BranchOps[] = {CCVal,  Target, LHS, RHS };
//


	return CurDAG->getMachineNode(opCode, N, MVT::Other, BranchOps);



}


SDNode *TriCoreDAGToDAGISel::Select(SDNode *N) {

	SDLoc dl(N);

  // Dump information about the Node being selected
  DEBUG(errs().changeColor(raw_ostream::GREEN) << "Selecting: ");
  DEBUG(N->dump(CurDAG));
  DEBUG(errs() << "\n");

  switch (N->getOpcode()) {
  case ISD::Constant:
    return SelectMoveImmediate(N);
//  case ISD::STORE:
//  	outs().changeColor(raw_ostream::GREEN) << "This is a store!\n";
//  	outs().changeColor(raw_ostream::WHITE);
//  	break;
//  case ISD::BR_CC:
//  	return SelectConditionalBranch(N);
  case ISD::FrameIndex: {
   	//FrameIndexSDNode *FSDNode = cast<FrameIndexSDNode>(N);
  	int FI = cast<FrameIndexSDNode>(N)->getIndex();
  	SDValue TFI = CurDAG->getTargetFrameIndex(FI, MVT::i32);
  	if (N->hasOneUse()) {

  	    	return CurDAG->SelectNodeTo(N, TriCore::ADDrc, MVT::i32, TFI,
  																			CurDAG->getTargetConstant(0, dl, MVT::i32));

  	    }
  	return CurDAG->getMachineNode(TriCore::ADDrc, dl, MVT::i32, TFI,
																CurDAG->getTargetConstant(0, dl, MVT::i32));
  	}
//  case ISD::LOAD:
//  	outs().changeColor(raw_ostream::BLUE,1) <<"This is a load\n";
//  	outs().changeColor(raw_ostream::WHITE,0);
//  	break;
//  case ISD::TargetGlobalAddress:
//  	outs().changeColor(raw_ostream::BLUE,1) <<"This is a TargetGlobalAddress\n";
//		outs().changeColor(raw_ostream::WHITE,0);
//
//		break;
//  case ISD::ADD:
//    	outs().changeColor(raw_ostream::BLUE,1) <<"This is a ADD\n";
//  		outs().changeColor(raw_ostream::WHITE,0);
//
//  		break;
  case TriCoreISD::BR_CC:

  	SDValue op1 = N->getOperand(0);
  	SDValue op2 = N->getOperand(1);

  	ConstantSDNode *op4 = cast<ConstantSDNode>(op2);
  	//CondCodeSDNode *op9 = cast<CondCodeSDNode>(op2);

  	outs().changeColor(raw_ostream::BLUE,1) <<"This is a BR_CC\n";
  	//op1.dump();
  	//op2.dump();
  	//op4->dump();
  	//outs() << printCondCode(op9->get()) <<"\n";
		outs().changeColor(raw_ostream::WHITE,0);
  	return SelectConditionalBranch(N, op4->getZExtValue());




  	break;


  }

  SDNode *ResNode = SelectCode(N);

	DEBUG(errs() << "=> ");
	if (ResNode == nullptr || ResNode == N)
		DEBUG(N->dump(CurDAG));
	else
		DEBUG(ResNode->dump(CurDAG));
	DEBUG(errs() << "\n");
  return ResNode;
}
/// createTriCoreISelDag - This pass converts a legalized DAG into a
/// TriCore-specific DAG, ready for instruction scheduling.
///
FunctionPass *llvm::createTriCoreISelDag(TriCoreTargetMachine &TM,
                                     CodeGenOpt::Level OptLevel) {
  return new TriCoreDAGToDAGISel(TM, OptLevel);
}
