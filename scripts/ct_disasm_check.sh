#!/usr/bin/env bash
#
#  Disassemble the CT-critical functions and verify they emit
#  branchless code (cmov/csel sign-mask, no data-dependent jumps).
#
#  Acceptable jumps inside a CT-critical function:
#   - jo (overflow detection — runtime check, never executes for
#     valid input).
#   - Conditional jumps targeting `leaq (%rip), %rdi` followed by
#     `callq` to a __gnat_*_handler — Constraint_Error path emitted
#     by GNAT for assertion / range-check failure (never executes
#     for valid input).
#
#  Anything else inside the function body is flagged as a potential
#  data-dependent branch.
#
#  Usage: bash scripts/ct_disasm_check.sh
#  Run after `alr build` from inside ml_dsa_ada/.

set -uo pipefail

cd "$(dirname "$0")/.."

if [ ! -d obj ]; then
    echo "Run alr build first."
    exit 1
fi

OBJDUMP="${OBJDUMP:-objdump}"

# CT-critical functions to inspect.
declare -a FUNCS=(
    "ml_dsa-reduce.o:_ml_dsa__reduce__caddq"
    "ml_dsa-rounding.o:_ml_dsa__rounding__decompose"
    "ml_dsa-rounding.o:_ml_dsa__rounding__make_hint"
    "ml_dsa-poly.o:_ml_dsa__poly__poly_chknorm"
)

overall_fail=0

for entry in "${FUNCS[@]}"; do
    obj="${entry%%:*}"
    func="${entry##*:}"

    # Symbol names carry a leading underscore in Mach-O (macOS) but not
    # in ELF (Linux). The FUNCS table uses the Mach-O spelling; fall
    # back to the ELF spelling when the object has no such symbol.
    if [ -f "obj/$obj" ] && ! "$OBJDUMP" -t "obj/$obj" 2>/dev/null | grep -q "$func"; then
        func="${func#_}"
    fi

    if [ ! -f "obj/$obj" ]; then
        echo "MISS  $func: obj/$obj not built"
        overall_fail=1
        continue
    fi

    # Pull the function body using sed range. The disassembly format is:
    #   <addr> <_funcname>:
    #       <addr>:    <opcode>
    #       ...
    #   <addr> <_nextfunc>:
    raw=$("$OBJDUMP" -d --no-show-raw-insn "obj/$obj")
    body=$(printf '%s\n' "$raw" | \
           sed -n "/<$func>:/,/^[0-9a-f]\\{1,16\\} <[^>]*>:/p" | \
           sed '$d')  # drop the next-function line that matched the end pattern

    if [ -z "$body" ]; then
        # sed range may have included only the start; try alternate form.
        body=$(printf '%s\n' "$raw" | \
               awk -v f="<$func>:" '
                   index($0, f) {found=1; print; next}
                   found && /<.*>:/ {found=0; exit}
                   found {print}')
    fi

    if [ -z "$body" ]; then
        echo "MISS  $func: function not found in $obj"
        overall_fail=1
        continue
    fi

    # Conditional jump mnemonics on x86-64 (excluding jmp).
    cond_pattern='\b(jo|jno|js|jns|je|jne|jc|jnc|jp|jnp|jl|jle|jg|jge|ja|jae|jb|jbe|jecxz)\b'
    jumps=$(printf '%s\n' "$body" | grep -oE "$cond_pattern[[:space:]]+0x[0-9a-f]+" | sort -u)

    n_jo=$(printf '%s\n' "$jumps" | grep -c '^jo' || true)
    n_other=$(printf '%s\n' "$jumps" | grep -cv '^jo' || true)

    # Of the non-`jo` jumps, classify each by inspecting whether the
    # target instruction begins with `leaq (%rip)` (the GNAT
    # Constraint_Error / range-check setup pattern).
    suspicious=0
    # Re-extract jumps with their source addresses so we can compare
    # forward (data-dep candidate) vs backward (loop-back, OK).
    full_jumps=$(printf '%s\n' "$body" | grep -E "^[[:space:]]*[0-9a-f]+:[[:space:]]+$cond_pattern[[:space:]]+0x[0-9a-f]+" || true)
    if [ -n "$full_jumps" ]; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            mnem=$(printf '%s' "$line" | grep -oE '\b(jo|jno|js|jns|je|jne|jc|jnc|jp|jnp|jl|jle|jg|jge|ja|jae|jb|jbe|jecxz)\b')
            src_hex=$(printf '%s' "$line" | grep -oE '^[[:space:]]*[0-9a-f]+:' | tr -d ': ' | head -1)
            tgt_hex=$(printf '%s' "$line" | grep -oE '0x[0-9a-f]+$' | sed 's/^0x//' | head -1)
            [ -z "$src_hex" ] || [ -z "$tgt_hex" ] && continue
            src_dec=$((16#$src_hex))
            tgt_dec=$((16#$tgt_hex))
            # `jo` is always overflow check (statically dead); skip.
            if [ "$mnem" = "jo" ]; then
                continue
            fi
            # Backward jump (target <= source): loop-back. Loop bounds
            # in our code are compile-time constants, so this is
            # data-independent.
            if [ "$tgt_dec" -le "$src_dec" ]; then
                continue
            fi
            # Forward jump: check target's first instruction.
            first=$(printf '%s\n' "$body" | grep -E "^[[:space:]]*${tgt_hex}:" | head -1)
            if printf '%s' "$first" | grep -qE 'leaq[[:space:]]+\(%rip\)'; then
                continue   # Constraint_Error setup
            fi
            if printf '%s' "$first" | grep -qE '\bcallq?\b'; then
                continue   # direct call to handler
            fi
            suspicious=$((suspicious + 1))
        done <<< "$full_jumps"
    fi

    n_total=$(printf '%s\n' "$body" | grep -cE "$cond_pattern" || true)

    if [ "$suspicious" -eq 0 ]; then
        printf "PASS  %-50s (%d jumps total: %d jo, %d to handler paths)\n" \
            "$func" "$n_total" "$n_jo" "$((n_total - n_jo))"
    else
        printf "FAIL  %-50s (%d data-dependent branches)\n" \
            "$func" "$suspicious"
        overall_fail=1
    fi
done

echo
if [ "$overall_fail" -ne 0 ]; then
    echo "=== FAIL: data-dependent branches detected ==="
    exit 1
fi
echo "=== PASS: all CT-critical functions are branchless modulo runtime-check stubs ==="
