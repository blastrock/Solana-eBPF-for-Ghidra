package ghidra.app.util.bin.format.elf.relocation;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.NotFoundException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class eBPFSolanaElfRelocationHandler extends ElfRelocationHandler {
	/// Start of the program bits (text and ro segments) in the memory map
	public static final long MM_PROGRAM_START = 0x100000000L;
	/// Start of the stack in the memory map
	public static final long MM_STACK_START = 0x200000000L;
	/// Start of the heap in the memory map
	public static final long MM_HEAP_START = 0x300000000L;
	/// Start of the input buffers in the memory map
	public static final long MM_INPUT_START = 0x400000000L;

    @Override
    public boolean canRelocate(ElfHeader elf) {
        return elf.e_machine() == ElfConstants.EM_BPF;
    }

    @Override
    public RelocationResult relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
                    Address relocationAddress) throws MemoryAccessException, NotFoundException {

        ElfHeader elf = elfRelocationContext.getElfHeader();
        if (elf.e_machine() != ElfConstants.EM_BPF) {
            return RelocationResult.FAILURE;
        }

        Program program = elfRelocationContext.getProgram();
        Memory memory = program.getMemory();

        int type = relocation.getType();
        if (type == eBPF_ElfRelocationConstants.R_BPF_NONE) {
            return RelocationResult.SKIPPED;
        }

        // String section_name = elfRelocationContext.relocationTable.getSectionToBeRelocated().getNameAsString();
        // if (section_name.toString().contains("debug")) {
        //     return RelocationResult.SKIPPED;
        // }

        SymbolTable table = program.getSymbolTable();
        int symbolIndex = relocation.getSymbolIndex();
        ElfSymbol symbol = elfRelocationContext.getSymbol(symbolIndex);
        String symbolName = symbol.getNameAsString();
        Address symbolAddr = elfRelocationContext.getSymbolAddress(symbol);

        // addend is either pulled from the relocation or the bytes in memory
		long addend =
			relocation.hasAddend() ? relocation.getAddend() : memory.getLong(relocationAddress);

        long symbolValue = elfRelocationContext.getSymbolValue(symbol);
        long symbolSize = symbol.getSize();

		long offset = relocationAddress.getOffset();

		long baseOffset = elfRelocationContext.getImageBaseWordAdjustmentOffset();
		Address imm_offset = relocationAddress.add(4);

        long new_value = 0;
        int byteLength = 4; // most relocations affect 4-bytes

        try {
            switch (type){
                case eBPF_ElfRelocationConstants.R_BPF_64_64: {
                    new_value = symbolValue;

                    Address refd_va = program.getAddressFactory().getDefaultAddressSpace().getAddress(memory.getInt(imm_offset));
                    new_value += refd_va.getOffset();

                    memory.setInt(imm_offset, (int)(new_value & 0xffffffff));
                    memory.setInt(imm_offset.add(8), (int)(new_value >> 32));
                    break;
                }
                // R_BPF_64_Relative
                case 8: {
                    new_value = symbolValue;

                    Address refd_va = program.getAddressFactory().getDefaultAddressSpace().getAddress(memory.getInt(imm_offset));
                    Address refd_pa = refd_va.add(baseOffset);
                    new_value += refd_pa.getOffset();
                    ElfSectionHeader text_section = elf.getSection(".text");
                    // check if split relocation across 2 instruction slots or single 64 bit value
                    long relativeOffset = offset - baseOffset;
                    if (text_section.getOffset() <= relativeOffset && relativeOffset <= text_section.getOffset() + text_section.getSize()) {
                        // write value split in two slots, high and slow
                        // elfRelocationContext.getLog().appendMsg(String.format("split set: %x = %x", imm_offset.getOffset(), value));
                        memory.setInt(imm_offset, (int)(new_value & 0xffffffff));
                        memory.setInt(imm_offset.add(8), (int)(new_value >> 32));
                    } else {
                        // elfRelocationContext.getLog().appendMsg(String.format("64 bit set: %x = %x", relocationAddress.getOffset(), refd_pa.getOffset()));
                        // 64 bit memory location, write entire 64 bit physical address directly
                        memory.setLong(relocationAddress, refd_pa.getOffset());
                    }
                }
                case eBPF_ElfRelocationConstants.R_BPF_64_32: {
                    int targetAddr;
                    String call_type;
                    // normally we would put the hash into the immediate field of
                    // the call but then we would have to resolve the call again
                    // in sleigh and I don't know how to do that
                    // therefore we just resolve the address relative to the current
                    // instruction and resolve it immediately :)
                    if (symbol.isFunction() && symbolValue != 0) {
                        // bpf call
                        long target_pc = symbolValue;// - text_section.getAddress();

                        // next instruction address that the call will be relative to
                        // minus modulo 8 to get to the address of the current instruction
                        // then add 8 to get to the next one
                        long this_pc = relocation.getOffset() - (relocation.getOffset() % 8) + 8 + baseOffset;
                        targetAddr = (int)((target_pc - this_pc)/8);
                        call_type = "function";
                    } else {
                        // syscall
                        call_type = "syscall";
                        // address of the symbol in the EXTERNAL section
                        long target_pc = symbolAddr.getOffset();
                        // next instruction address that the call will be relative to
                        // minus modulo 8 to get to the address of the current instruction
                        // then add 8 to get to the next one
                        long this_pc = relocation.getOffset() - (relocation.getOffset() % 8) + 8 + baseOffset;
                        targetAddr = (int)((target_pc - this_pc)/8);
                    }

                    memory.setInt(imm_offset, targetAddr);
                    // Listing listing = program.getListing();
                    // listing.setComment(relocationAddress, CodeUnit.EOL_COMMENT,
                    //	String.format("%s_%s", call_type, symbolName));
                    break;
                }
                default: {
                    if (symbolIndex == 0) {
                        markAsWarning(program, relocationAddress,
                                Long.toString(type), "applied relocation with symbol-index of 0", elfRelocationContext.getLog());
                    }
                    return RelocationResult.UNSUPPORTED;
                }
            }
        } catch (NullPointerException e) {  }
        return new RelocationResult(Status.APPLIED, byteLength);
    }
}
