---
title : "HTB Cyber Apocalypse CTF 2024"
categories : ["2024", "HackTheBox"]
---

## Introduction

저번 주에 `Friendly Maltese Citizens` 연합팀으로 HTB Cyber Apocalypse CTF에 참여해서 1등했다!

봤던 문제들을 정리해봤다.

### Metagaming - 325pts

`main.cpp`가 주어진다.

CTF 시작할 때 로그인이 안 돼서 늦게 봤는데 운 좋게 first blood했다.

#### main.cpp

```c++
// Use MSVC or `g++ -std=c++20`

#include <cstdint>
#include <array>
#include <iostream>
#include <numeric>
#include <type_traits>
#include <algorithm>
#include <variant>

#ifndef __noop
#define __noop
#endif

constexpr uint32_t rotr(const uint32_t value, const int shift) {
    return std::rotr(value, shift);
}

constexpr uint32_t rotl(const uint32_t value, const int shift) {
    return std::rotl(value, shift);
}

template<class, class>
constexpr bool is_same_v = false;

template<class Ty>
constexpr bool is_same_v<Ty, Ty> = true;

struct true_t {};
struct false_t {};

template<class Ty>
concept bool_t = is_same_v<Ty, true_t> || is_same_v<Ty, false_t>;

template<bool Val>
struct to_bool {
    using T = false_t;
};
template<>
struct to_bool<true> {
    using T = true_t;
};
template<bool Val>
using to_bool_t = typename to_bool<Val>::T;
template<bool_t Ty>
constexpr bool from_bool_v = is_same_v<Ty, true_t>;

template<char C>
struct char_value_t {
    [[nodiscard]] constexpr static char value() {
        return C;
    }
};

struct a : char_value_t<'a'> {};
struct b : char_value_t<'b'> {};
struct c : char_value_t<'c'> {};
struct d : char_value_t<'d'> {};
struct e : char_value_t<'e'> {};
struct f : char_value_t<'f'> {};
struct g : char_value_t<'g'> {};
struct h : char_value_t<'h'> {};
struct i : char_value_t<'i'> {};
struct j : char_value_t<'j'> {};
struct k : char_value_t<'k'> {};
struct l : char_value_t<'l'> {};
struct m : char_value_t<'m'> {};
struct n : char_value_t<'n'> {};
struct o : char_value_t<'o'> {};
struct p : char_value_t<'p'> {};
struct q : char_value_t<'q'> {};
struct r : char_value_t<'r'> {};
struct s : char_value_t<'s'> {};
struct t : char_value_t<'t'> {};
struct u : char_value_t<'u'> {};
struct v : char_value_t<'v'> {};
struct w : char_value_t<'w'> {};
struct x : char_value_t<'x'> {};
struct y : char_value_t<'y'> {};
struct z : char_value_t<'z'> {};
struct A : char_value_t<'A'> {};
struct B : char_value_t<'B'> {};
struct C : char_value_t<'C'> {};
struct D : char_value_t<'D'> {};
struct E : char_value_t<'E'> {};
struct F : char_value_t<'F'> {};
struct G : char_value_t<'G'> {};
struct H : char_value_t<'H'> {};
struct I : char_value_t<'I'> {};
struct J : char_value_t<'J'> {};
struct K : char_value_t<'K'> {};
struct L : char_value_t<'L'> {};
struct M : char_value_t<'M'> {};
struct N : char_value_t<'N'> {};
struct O : char_value_t<'O'> {};
struct P : char_value_t<'P'> {};
struct Q : char_value_t<'Q'> {};
struct R : char_value_t<'R'> {};
struct S : char_value_t<'S'> {};
struct T : char_value_t<'T'> {};
struct U : char_value_t<'U'> {};
struct V : char_value_t<'V'> {};
struct W : char_value_t<'W'> {};
struct X : char_value_t<'X'> {};
struct Y : char_value_t<'Y'> {};
struct Z : char_value_t<'Z'> {};
struct num_1 : char_value_t<'1'> {};
struct num_2 : char_value_t<'2'> {};
struct num_3 : char_value_t<'3'> {};
struct num_4 : char_value_t<'4'> {};
struct num_5 : char_value_t<'5'> {};
struct num_6 : char_value_t<'6'> {};
struct num_7 : char_value_t<'7'> {};
struct num_8 : char_value_t<'8'> {};
struct num_9 : char_value_t<'9'> {};
struct num_0 : char_value_t<'0'> {};
// SOMEWHAT SPECIAL CHARACTERS
struct bracket_open : char_value_t<'{'> {};
struct bracket_close : char_value_t<'}'> {};
struct underscore : char_value_t<'_'> {};

template<class Ty, class... Types>
concept is_any_of_t = std::disjunction_v<std::is_same<Ty, Types>...>;

template<typename Ty>
concept any_legit_char_t = is_any_of_t<Ty, a, b, c, d, e, f, g, h, i, j, k, l, m, n,
                                       o, p, q, r, s, t, u, v, w, x, y, z, A, B, C, D,
                                       E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T,
                                       U, V, W, X, Y, Z, num_1, num_2, num_3, num_4, num_5,
                                       num_6, num_7, num_8, num_9, num_0, bracket_open,
                                       bracket_close, underscore>;

template<class... values>
struct flag_t {
    [[nodiscard]] static constexpr size_t size() {
        return sizeof...(values);
    }

    template<typename Ty = char>
    [[nodiscard]] static constexpr Ty at(const std::size_t i) {
        constexpr char values_values[] = {values::value()...};
        return static_cast<Ty>(values_values[i]);
    }
};

template<size_t Footprint>
struct cxstring {
    char data[Footprint]{};
    [[nodiscard]] constexpr size_t size() const {
        return Footprint - 1;
    }
    constexpr /* implicit */ cxstring(const char (&init)[Footprint]) {// NOLINT
        std::copy_n(init, Footprint, data);
    }
};

template<auto str>
struct type_string {
    [[nodiscard]] static constexpr const char *data() {
        return str.data;
    }
    [[nodiscard]] static constexpr size_t size() {
        return str.size();
    }
};

template<class P>
auto parse_flag(P) -> P { return {}; }

template<char Chr, char... Rest, class... Bs>
auto parse_flag(flag_t<Bs...>) -> decltype(parse_flag<Rest...>(flag_t<Bs..., char_value_t<Chr>>{})) { return {}; }

template<class lambda_t, size_t... I>
constexpr auto make_flag(lambda_t lambda [[maybe_unused]], std::index_sequence<I...>) {
    return decltype(parse_flag<lambda()[I]...>(flag_t<>{})){};
}

template<cxstring str>
constexpr auto operator"" _flag() noexcept {
    constexpr auto s = type_string<str>{};
    return make_flag([&]() constexpr { return (s.data()); }, std::make_index_sequence<s.size()>{});
}

struct insn_t {
    uint32_t opcode = 0;
    uint32_t op0 = 0;
    uint32_t op1 = 0;
};

template<typename = std::monostate>
concept always_false_v = false;

template<insn_t>
concept always_false_insn_v = false;

template<flag_t Flag, insn_t... Instructions>
struct program_t {
    using R = std::array<uint32_t, 15>;

    template<insn_t Insn>
    static constexpr void execute_one(R &regs) {
        if constexpr (Insn.opcode == 0) {
            regs[Insn.op0] = Flag.at(Insn.op1);
        } else if constexpr (Insn.opcode == 1) {
            regs[Insn.op0] = Insn.op1;
        } else if constexpr (Insn.opcode == 2) {
            regs[Insn.op0] ^= Insn.op1;
        } else if constexpr (Insn.opcode == 3) {
            regs[Insn.op0] ^= regs[Insn.op1];
        } else if constexpr (Insn.opcode == 4) {
            regs[Insn.op0] |= Insn.op1;
        } else if constexpr (Insn.opcode == 5) {
            regs[Insn.op0] |= regs[Insn.op1];
        } else if constexpr (Insn.opcode == 6) {
            regs[Insn.op0] &= Insn.op1;
        } else if constexpr (Insn.opcode == 7) {
            regs[Insn.op0] &= regs[Insn.op1];
        } else if constexpr (Insn.opcode == 8) {
            regs[Insn.op0] += Insn.op1;
        } else if constexpr (Insn.opcode == 9) {
            regs[Insn.op0] += regs[Insn.op1];
        } else if constexpr (Insn.opcode == 10) {
            regs[Insn.op0] -= Insn.op1;
        } else if constexpr (Insn.opcode == 11) {
            regs[Insn.op0] -= regs[Insn.op1];
        } else if constexpr (Insn.opcode == 12) {
            regs[Insn.op0] *= Insn.op1;
        } else if constexpr (Insn.opcode == 13) {
            regs[Insn.op0] *= regs[Insn.op1];
        } else if constexpr (Insn.opcode == 14) {
            __noop;
        } else if constexpr (Insn.opcode == 15) {
            __noop;
            __noop;
        } else if constexpr (Insn.opcode == 16) {
            regs[Insn.op0] = rotr(regs[Insn.op0], Insn.op1);
        } else if constexpr (Insn.opcode == 17) {
            regs[Insn.op0] = rotr(regs[Insn.op0], regs[Insn.op1]);
        } else if constexpr (Insn.opcode == 18) {
            regs[Insn.op0] = rotl(regs[Insn.op0], Insn.op1);
        } else if constexpr (Insn.opcode == 19) {
            regs[Insn.op0] = rotl(regs[Insn.op0], regs[Insn.op1]);
        } else if constexpr (Insn.opcode == 20) {
            regs[Insn.op0] = regs[Insn.op1];
        } else if constexpr (Insn.opcode == 21) {
            regs[Insn.op0] = 0;
        } else if constexpr (Insn.opcode == 22) {
            regs[Insn.op0] >>= Insn.op1;
        } else if constexpr (Insn.opcode == 23) {
            regs[Insn.op0] >>= regs[Insn.op1];
        } else if constexpr (Insn.opcode == 24) {
            regs[Insn.op0] <<= Insn.op1;
        } else if constexpr (Insn.opcode == 25) {
            regs[Insn.op0] <<= regs[Insn.op1];
        } else {
            static_assert(always_false_insn_v<Insn>);
        }
    }

    template<std::size_t... Is>
    static constexpr void execute_impl(R &regs, std::index_sequence<Is...>) {
        (execute_one<Instructions>(regs), ...);
    }

    static constexpr void execute(R &regs) {
        execute_impl(regs, std::make_index_sequence<sizeof...(Instructions)>{});
    }

    static constexpr R registers = []() -> R {
        R arr = {};
        execute(arr);
        return arr;
    }();
};

int main() {
    /// Modify this text              vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
    [[maybe_unused]] auto flag = "HTB{___________________________________}"_flag;
    /// Modify this text              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    static_assert(decltype(flag)::size() == 40);

    using program = program_t<flag, insn_t(12, 13, 10), insn_t(21, 0, 0), insn_t(0, 13, 13), insn_t(0, 14, 0), insn_t(15, 11, 12), insn_t(24, 14, 0), insn_t(5, 0, 14), insn_t(0, 14, 1), insn_t(7, 11, 11), insn_t(24, 14, 8), insn_t(5, 0, 14), insn_t(0, 14, 2), insn_t(2, 10, 11), insn_t(24, 14, 16), insn_t(18, 12, 11), insn_t(5, 0, 14), insn_t(0, 14, 3), insn_t(0, 11, 11), insn_t(24, 14, 24), insn_t(13, 10, 10), insn_t(5, 0, 14), insn_t(2, 11, 13), insn_t(21, 1, 0), insn_t(0, 14, 4), insn_t(24, 14, 0), insn_t(5, 1, 14), insn_t(6, 11, 12), insn_t(0, 14, 5), insn_t(8, 10, 10), insn_t(24, 14, 8), insn_t(11, 12, 11), insn_t(5, 1, 14), insn_t(0, 14, 6), insn_t(0, 12, 10), insn_t(24, 14, 16), insn_t(9, 10, 13), insn_t(5, 1, 14), insn_t(0, 14, 7), insn_t(13, 12, 12), insn_t(24, 14, 24), insn_t(15, 10, 12), insn_t(5, 1, 14), insn_t(21, 2, 0), insn_t(20, 13, 13), insn_t(0, 14, 8), insn_t(24, 14, 0), insn_t(19, 10, 11), insn_t(5, 2, 14), insn_t(6, 12, 10), insn_t(0, 14, 9), insn_t(8, 11, 11), insn_t(24, 14, 8), insn_t(5, 2, 14), insn_t(0, 14, 10), insn_t(4, 11, 12), insn_t(24, 14, 16), insn_t(5, 2, 14), insn_t(0, 14, 11), insn_t(24, 14, 24), insn_t(4, 13, 12), insn_t(5, 2, 14), insn_t(21, 3, 0), insn_t(14, 10, 12), insn_t(0, 14, 12), insn_t(13, 10, 11), insn_t(24, 14, 0), insn_t(16, 10, 10), insn_t(5, 3, 14), insn_t(5, 11, 12), insn_t(0, 14, 13), insn_t(12, 10, 13), insn_t(24, 14, 8), insn_t(2, 10, 13), insn_t(5, 3, 14), insn_t(20, 11, 11), insn_t(0, 14, 14), insn_t(24, 14, 16), insn_t(18, 13, 11), insn_t(5, 3, 14), insn_t(6, 11, 13), insn_t(0, 14, 15), insn_t(24, 14, 24), insn_t(4, 11, 10), insn_t(5, 3, 14), insn_t(21, 4, 0), insn_t(15, 13, 11), insn_t(0, 14, 16), insn_t(6, 10, 10), insn_t(24, 14, 0), insn_t(14, 10, 12), insn_t(5, 4, 14), insn_t(0, 14, 17), insn_t(12, 13, 13), insn_t(24, 14, 8), insn_t(19, 11, 10), insn_t(5, 4, 14), insn_t(0, 14, 18), insn_t(17, 13, 12), insn_t(24, 14, 16), insn_t(5, 4, 14), insn_t(0, 14, 19), insn_t(24, 14, 24), insn_t(21, 12, 10), insn_t(5, 4, 14), insn_t(13, 13, 10), insn_t(21, 5, 0), insn_t(0, 14, 20), insn_t(19, 10, 13), insn_t(24, 14, 0), insn_t(5, 5, 14), insn_t(0, 14, 21), insn_t(24, 14, 8), insn_t(8, 13, 13), insn_t(5, 5, 14), insn_t(0, 14, 22), insn_t(16, 13, 11), insn_t(24, 14, 16), insn_t(10, 10, 13), insn_t(5, 5, 14), insn_t(7, 10, 12), insn_t(0, 14, 23), insn_t(19, 13, 10), insn_t(24, 14, 24), insn_t(5, 5, 14), insn_t(17, 12, 10), insn_t(21, 6, 0), insn_t(16, 11, 10), insn_t(0, 14, 24), insn_t(24, 14, 0), insn_t(10, 11, 10), insn_t(5, 6, 14), insn_t(0, 14, 25), insn_t(24, 14, 8), insn_t(7, 10, 12), insn_t(5, 6, 14), insn_t(0, 14, 26), insn_t(16, 12, 11), insn_t(24, 14, 16), insn_t(3, 11, 10), insn_t(5, 6, 14), insn_t(15, 11, 13), insn_t(0, 14, 27), insn_t(4, 12, 13), insn_t(24, 14, 24), insn_t(5, 6, 14), insn_t(14, 11, 13), insn_t(21, 7, 0), insn_t(0, 14, 28), insn_t(21, 13, 11), insn_t(24, 14, 0), insn_t(7, 12, 11), insn_t(5, 7, 14), insn_t(17, 11, 10), insn_t(0, 14, 29), insn_t(24, 14, 8), insn_t(5, 7, 14), insn_t(0, 14, 30), insn_t(12, 10, 10), insn_t(24, 14, 16), insn_t(5, 7, 14), insn_t(0, 14, 31), insn_t(20, 10, 10), insn_t(24, 14, 24), insn_t(5, 7, 14), insn_t(21, 8, 0), insn_t(18, 10, 12), insn_t(0, 14, 32), insn_t(9, 11, 11), insn_t(24, 14, 0), insn_t(21, 12, 11), insn_t(5, 8, 14), insn_t(0, 14, 33), insn_t(24, 14, 8), insn_t(19, 10, 13), insn_t(5, 8, 14), insn_t(8, 12, 13), insn_t(0, 14, 34), insn_t(24, 14, 16), insn_t(5, 8, 14), insn_t(8, 10, 10), insn_t(0, 14, 35), insn_t(24, 14, 24), insn_t(21, 13, 10), insn_t(5, 8, 14), insn_t(0, 12, 10), insn_t(21, 9, 0), insn_t(0, 14, 36), insn_t(24, 14, 0), insn_t(5, 9, 14), insn_t(17, 11, 11), insn_t(0, 14, 37), insn_t(14, 10, 13), insn_t(24, 14, 8), insn_t(5, 9, 14), insn_t(4, 10, 11), insn_t(0, 14, 38), insn_t(13, 11, 13), insn_t(24, 14, 16), insn_t(5, 9, 14), insn_t(0, 14, 39), insn_t(10, 11, 10), insn_t(24, 14, 24), insn_t(20, 13, 13), insn_t(5, 9, 14), insn_t(6, 12, 11), insn_t(21, 14, 0), insn_t(8, 0, 2769503260), insn_t(10, 0, 997841014), insn_t(19, 12, 11), insn_t(2, 0, 4065997671), insn_t(5, 13, 11), insn_t(8, 0, 690011675), insn_t(15, 11, 11), insn_t(8, 0, 540576667), insn_t(2, 0, 1618285201), insn_t(8, 0, 1123989331), insn_t(8, 0, 1914950564), insn_t(8, 0, 4213669998), insn_t(21, 13, 11), insn_t(8, 0, 1529621790), insn_t(10, 0, 865446746), insn_t(2, 10, 11), insn_t(8, 0, 449019059), insn_t(16, 13, 11), insn_t(8, 0, 906976959), insn_t(6, 10, 10), insn_t(8, 0, 892028723), insn_t(10, 0, 1040131328), insn_t(2, 0, 3854135066), insn_t(2, 0, 4133925041), insn_t(2, 0, 1738396966), insn_t(2, 12, 12), insn_t(8, 0, 550277338), insn_t(10, 0, 1043160697), insn_t(2, 1, 1176768057), insn_t(10, 1, 2368952475), insn_t(8, 12, 11), insn_t(2, 1, 2826144967), insn_t(8, 1, 1275301297), insn_t(10, 1, 2955899422), insn_t(2, 1, 2241699318), insn_t(12, 11, 10), insn_t(8, 1, 537794314), insn_t(11, 13, 10), insn_t(8, 1, 473021534), insn_t(17, 12, 13), insn_t(8, 1, 2381227371), insn_t(10, 1, 3973380876), insn_t(10, 1, 1728990628), insn_t(6, 11, 13), insn_t(8, 1, 2974252696), insn_t(0, 11, 11), insn_t(8, 1, 1912236055), insn_t(2, 1, 3620744853), insn_t(3, 10, 13), insn_t(2, 1, 2628426447), insn_t(11, 13, 12), insn_t(10, 1, 486914414), insn_t(16, 11, 12), insn_t(10, 1, 1187047173), insn_t(14, 12, 11), insn_t(2, 2, 3103274804), insn_t(13, 10, 10), insn_t(8, 2, 3320200805), insn_t(8, 2, 3846589389), insn_t(1, 13, 13), insn_t(2, 2, 2724573159), insn_t(10, 2, 1483327425), insn_t(2, 2, 1957985324), insn_t(14, 13, 12), insn_t(10, 2, 1467602691), insn_t(8, 2, 3142557962), insn_t(2, 13, 12), insn_t(2, 2, 2525769395), insn_t(8, 2, 3681119483), insn_t(8, 12, 11), insn_t(10, 2, 1041439413), insn_t(10, 2, 1042206298), insn_t(2, 2, 527001246), insn_t(20, 10, 13), insn_t(10, 2, 855860613), insn_t(8, 10, 10), insn_t(8, 2, 1865979270), insn_t(1, 13, 10), insn_t(8, 2, 2752636085), insn_t(2, 2, 1389650363), insn_t(10, 2, 2721642985), insn_t(18, 10, 11), insn_t(8, 2, 3276518041), insn_t(15, 10, 10), insn_t(2, 2, 1965130376), insn_t(2, 3, 3557111558), insn_t(2, 3, 3031574352), insn_t(16, 12, 10), insn_t(10, 3, 4226755821), insn_t(8, 3, 2624879637), insn_t(8, 3, 1381275708), insn_t(2, 3, 3310620882), insn_t(2, 3, 2475591380), insn_t(8, 3, 405408383), insn_t(2, 3, 2291319543), insn_t(0, 12, 12), insn_t(8, 3, 4144538489), insn_t(2, 3, 3878256896), insn_t(6, 11, 10), insn_t(10, 3, 2243529248), insn_t(10, 3, 561931268), insn_t(11, 11, 12), insn_t(10, 3, 3076955709), insn_t(18, 12, 13), insn_t(8, 3, 2019584073), insn_t(10, 13, 12), insn_t(8, 3, 1712479912), insn_t(18, 11, 11), insn_t(2, 3, 2804447380), insn_t(17, 10, 10), insn_t(10, 3, 2957126100), insn_t(18, 13, 13), insn_t(8, 3, 1368187437), insn_t(17, 10, 12), insn_t(8, 3, 3586129298), insn_t(10, 4, 1229526732), insn_t(19, 11, 11), insn_t(10, 4, 2759768797), insn_t(1, 10, 13), insn_t(2, 4, 2112449396), insn_t(10, 4, 1212917601), insn_t(2, 4, 1524771736), insn_t(8, 4, 3146530277), insn_t(2, 4, 2997906889), insn_t(16, 12, 10), insn_t(8, 4, 4135691751), insn_t(8, 4, 1960868242), insn_t(6, 12, 12), insn_t(10, 4, 2775657353), insn_t(16, 10, 13), insn_t(8, 4, 1451259226), insn_t(8, 4, 607382171), insn_t(13, 13, 13), insn_t(10, 4, 357643050), insn_t(2, 4, 2020402776), insn_t(8, 5, 2408165152), insn_t(13, 12, 10), insn_t(2, 5, 806913563), insn_t(10, 5, 772591592), insn_t(20, 13, 11), insn_t(2, 5, 2211018781), insn_t(10, 5, 2523354879), insn_t(8, 5, 2549720391), insn_t(2, 5, 3908178996), insn_t(2, 5, 1299171929), insn_t(8, 5, 512513885), insn_t(10, 5, 2617924552), insn_t(1, 12, 13), insn_t(8, 5, 390960442), insn_t(12, 11, 13), insn_t(8, 5, 1248271133), insn_t(8, 5, 2114382155), insn_t(1, 10, 13), insn_t(10, 5, 2078863299), insn_t(20, 12, 12), insn_t(8, 5, 2857504053), insn_t(10, 5, 4271947727), insn_t(2, 6, 2238126367), insn_t(2, 6, 1544827193), insn_t(8, 6, 4094800187), insn_t(2, 6, 3461906189), insn_t(10, 6, 1812592759), insn_t(2, 6, 1506702473), insn_t(8, 6, 536175198), insn_t(2, 6, 1303821297), insn_t(8, 6, 715409343), insn_t(2, 6, 4094566992), insn_t(14, 10, 11), insn_t(2, 6, 1890141105), insn_t(0, 13, 13), insn_t(2, 6, 3143319360), insn_t(10, 7, 696930856), insn_t(2, 7, 926450200), insn_t(8, 7, 352056373), insn_t(20, 13, 11), insn_t(10, 7, 3857703071), insn_t(8, 7, 3212660135), insn_t(5, 12, 10), insn_t(10, 7, 3854876250), insn_t(21, 12, 11), insn_t(8, 7, 3648688720), insn_t(2, 7, 2732629817), insn_t(4, 10, 12), insn_t(10, 7, 2285138643), insn_t(18, 10, 13), insn_t(2, 7, 2255852466), insn_t(2, 7, 2537336944), insn_t(3, 10, 13), insn_t(2, 7, 4257606405), insn_t(10, 8, 3703184638), insn_t(7, 11, 10), insn_t(10, 8, 2165056562), insn_t(8, 8, 2217220568), insn_t(19, 10, 12), insn_t(8, 8, 2088084496), insn_t(15, 13, 10), insn_t(8, 8, 443074220), insn_t(16, 13, 12), insn_t(10, 8, 1298336973), insn_t(2, 13, 11), insn_t(8, 8, 822378456), insn_t(19, 11, 12), insn_t(8, 8, 2154711985), insn_t(0, 11, 12), insn_t(10, 8, 430757325), insn_t(2, 12, 10), insn_t(2, 8, 2521672196), insn_t(10, 9, 532704100), insn_t(10, 9, 2519542932), insn_t(2, 9, 2451309277), insn_t(2, 9, 3957445476), insn_t(5, 10, 10), insn_t(8, 9, 2583554449), insn_t(10, 9, 1149665327), insn_t(12, 13, 12), insn_t(8, 9, 3053959226), insn_t(0, 10, 10), insn_t(8, 9, 3693780276), insn_t(15, 11, 10), insn_t(2, 9, 609918789), insn_t(2, 9, 2778221635), insn_t(16, 13, 10), insn_t(8, 9, 3133754553), insn_t(8, 11, 13), insn_t(8, 9, 3961507338), insn_t(2, 9, 1829237263), insn_t(16, 11, 13), insn_t(2, 9, 2472519933), insn_t(6, 12, 12), insn_t(8, 9, 4061630846), insn_t(10, 9, 1181684786), insn_t(13, 10, 11), insn_t(10, 9, 390349075), insn_t(8, 9, 2883917626), insn_t(10, 9, 3733394420), insn_t(10, 12, 12), insn_t(2, 9, 3895283827), insn_t(20, 10, 11), insn_t(2, 9, 2257053750), insn_t(10, 9, 2770821931), insn_t(18, 10, 13), insn_t(2, 9, 477834410), insn_t(19, 13, 12), insn_t(3, 0, 1), insn_t(12, 12, 12), insn_t(3, 1, 2), insn_t(11, 13, 11), insn_t(3, 2, 3), insn_t(3, 3, 4), insn_t(3, 4, 5), insn_t(1, 13, 13), insn_t(3, 5, 6), insn_t(7, 11, 11), insn_t(3, 6, 7), insn_t(4, 10, 12), insn_t(3, 7, 8), insn_t(18, 12, 12), insn_t(3, 8, 9), insn_t(21, 12, 10), insn_t(3, 9, 10)>;
    static_assert(program::registers[0] == 0x3ee88722 && program::registers[1] == 0xecbdbe2 && program::registers[2] == 0x60b843c4 && program::registers[3] == 0x5da67c7 && program::registers[4] == 0x171ef1e9 && program::registers[5] == 0x52d5b3f7 && program::registers[6] == 0x3ae718c0 && program::registers[7] == 0x8b4aacc2 && program::registers[8] == 0xe5cf78dd && program::registers[9] == 0x4a848edf && program::registers[10] == 0x8f && program::registers[11] == 0x4180000 && program::registers[12] == 0x0 && program::registers[13] == 0xd && program::registers[14] == 0x0, "Ah! Your flag is invalid.");
}
```

```shell
$ g++ -std=c++20 -o main main.cpp
main.cpp: In function ‘int main()’:
main.cpp:284:41: error: static assertion failed: Ah! Your flag is invalid.
  284 |     static_assert(program::registers[0] == 0x3ee88722 && program::registers[1] == 0xecbdbe2 && program::registers[2] == 0x60b843c4 && program::registers[3] == 0x5da67c7 && program::registers[4] == 0x171ef1e9 && program::registers[5] == 0x52d5b3f7 && program::registers[6] == 0x3ae718c0 && program::registers[7] == 0x8b4aacc2 && program::registers[8] == 0xe5cf78dd && program::registers[9] == 0x4a848edf && program::registers[10] == 0x8f && program::registers[11] == 0x4180000 && program::registers[12] == 0x0 && program::registers[13] == 0xd && program::registers[14] == 0x0, "Ah! Your flag is invalid.");
```

컴파일해보면 `static_assert`에서 에러가 난다.

`program::registers` 값이 각 hex값과 같아지는 flag를 찾아야 한다.

#### solution

코드에 VM연산이 보기 쉽게 적혀있다.

emulator를 짜고 z3연산으로 바꿔줘서 플래그를 획득했다.

#### sol.py

```python
from z3 import *

def parse(opcode, op0, op1):
    if opcode == 0:
        R[op0] = flag[op1]
    elif opcode == 1:
        R[op0] = BitVecVal(op1, 32)
    elif opcode == 2:
        R[op0] ^= op1
    elif opcode == 3:
        R[op0] ^= R[op1]
    elif opcode == 4:
        R[op0] |= op1
    elif opcode == 5:
        R[op0] |= R[op1]
    elif opcode == 6:
        R[op0] &= op1
    elif opcode == 7:
        R[op0] &= R[op1]
    elif opcode == 8:
        R[op0] += op1
    elif opcode == 9:
        R[op0] += R[op1]
    elif opcode == 10:
        R[op0] -= op1
    elif opcode == 11:
        R[op0] -= R[op1]
    elif opcode == 12:
        R[op0] *= op1
    elif opcode == 13:
        R[op0] *= R[op1]
    elif opcode == 16:
        R[op0] = RotateRight(R[op0], op1)
    elif opcode == 17:
        R[op0] = RotateRight(R[op0], R[op1])
    elif opcode == 18:
        R[op0] = RotateLeft(R[op0], op1)
    elif opcode == 19:
        R[op0] = RotateLeft(R[op0], R[op1])
    elif opcode == 20:
        R[op0] = R[op1]
    elif opcode == 21:
        R[op0] = BitVecVal(0, 32)
    elif opcode == 22:
        R[op0] = LShR(R[op0], op1)
    elif opcode == 23:
        R[op0] = LShR(R[op0], R[op1])
    elif opcode == 24:
        R[op0] = (R[op0] << op1) & 0xffffffff
    elif opcode == 25:
        R[op0] = (R[op0] << R[op1]) & 0xffffffff        

    R[op0] &= 0xffffffff

opcodes = [[12, 13, 10], [21, 0, 0], [0, 13, 13], [0, 14, 0], [15, 11, 12], [24, 14, 0], [5, 0, 14], [0, 14, 1], [7, 11, 11], [24, 14, 8], [5, 0, 14], [0, 14, 2], [2, 10, 11], [24, 14, 16], [18, 12, 11], [5, 0, 14], [0, 14, 3], [0, 11, 11], [24, 14, 24], [13, 10, 10], [5, 0, 14], [2, 11, 13], [21, 1, 0], [0, 14, 4], [24, 14, 0], [5, 1, 14], [6, 11, 12], [0, 14, 5], [8, 10, 10], [24, 14, 8], [11, 12, 11], [5, 1, 14], [0, 14, 6], [0, 12, 10], [24, 14, 16], [9, 10, 13], [5, 1, 14], [0, 14, 7], [13, 12, 12], [24, 14, 24], [15, 10, 12], [5, 1, 14], [21, 2, 0], [20, 13, 13], [0, 14, 8], [24, 14, 0], [19, 10, 11], [5, 2, 14], [6, 12, 10], [0, 14, 9], [8, 11, 11], [24, 14, 8], [5, 2, 14], [0, 14, 10], [4, 11, 12], [24, 14, 16], [5, 2, 14], [0, 14, 11], [24, 14, 24], [4, 13, 12], [5, 2, 14], [21, 3, 0], [14, 10, 12], [0, 14, 12], [13, 10, 11], [24, 14, 0], [16, 10, 10], [5, 3, 14], [5, 11, 12], [0, 14, 13], [12, 10, 13], [24, 14, 8], [2, 10, 13], [5, 3, 14], [20, 11, 11], [0, 14, 14], [24, 14, 16], [18, 13, 11], [5, 3, 14], [6, 11, 13], [0, 14, 15], [24, 14, 24], [4, 11, 10], [5, 3, 14], [21, 4, 0], [15, 13, 11], [0, 14, 16], [6, 10, 10], [24, 14, 0], [14, 10, 12], [5, 4, 14], [0, 14, 17], [12, 13, 13], [24, 14, 8], [19, 11, 10], [5, 4, 14], [0, 14, 18], [17, 13, 12], [24, 14, 16], [5, 4, 14], [0, 14, 19], [24, 14, 24], [21, 12, 10], [5, 4, 14], [13, 13, 10], [21, 5, 0], [0, 14, 20], [19, 10, 13], [24, 14, 0], [5, 5, 14], [0, 14, 21], [24, 14, 8], [8, 13, 13], [5, 5, 14], [0, 14, 22], [16, 13, 11], [24, 14, 16], [10, 10, 13], [5, 5, 14], [7, 10, 12], [0, 14, 23], [19, 13, 10], [24, 14, 24], [5, 5, 14], [17, 12, 10], [21, 6, 0], [16, 11, 10], [0, 14, 24], [24, 14, 0], [10, 11, 10], [5, 6, 14], [0, 14, 25], [24, 14, 8], [7, 10, 12], [5, 6, 14], [0, 14, 26], [16, 12, 11], [24, 14, 16], [3, 11, 10], [5, 6, 14], [15, 11, 13], [0, 14, 27], [4, 12, 13], [24, 14, 24], [5, 6, 14], [14, 11, 13], [21, 7, 0], [0, 14, 28], [21, 13, 11], [24, 14, 0], [7, 12, 11], [5, 7, 14], [17, 11, 10], [0, 14, 29], [24, 14, 8], [5, 7, 14], [0, 14, 30], [12, 10, 10], [24, 14, 16], [5, 7, 14], [0, 14, 31], [20, 10, 10], [24, 14, 24], [5, 7, 14], [21, 8, 0], [18, 10, 12], [0, 14, 32], [9, 11, 11], [24, 14, 0], [21, 12, 11], [5, 8, 14], [0, 14, 33], [24, 14, 8], [19, 10, 13], [5, 8, 14], [8, 12, 13], [0, 14, 34], [24, 14, 16], [5, 8, 14], [8, 10, 10], [0, 14, 35], [24, 14, 24], [21, 13, 10], [5, 8, 14], [0, 12, 10], [21, 9, 0], [0, 14, 36], [24, 14, 0], [5, 9, 14], [17, 11, 11], [0, 14, 37], [14, 10, 13], [24, 14, 8], [5, 9, 14], [4, 10, 11], [0, 14, 38], [13, 11, 13], [24, 14, 16], [5, 9, 14], [0, 14, 39], [10, 11, 10], [24, 14, 24], [20, 13, 13], [5, 9, 14], [6, 12, 11], [21, 14, 0], [8, 0, 2769503260], [10, 0, 997841014], [19, 12, 11], [2, 0, 4065997671], [5, 13, 11], [8, 0, 690011675], [15, 11, 11], [8, 0, 540576667], [2, 0, 1618285201], [8, 0, 1123989331], [8, 0, 1914950564], [8, 0, 4213669998], [21, 13, 11], [8, 0, 1529621790], [10, 0, 865446746], [2, 10, 11], [8, 0, 449019059], [16, 13, 11], [8, 0, 906976959], [6, 10, 10], [8, 0, 892028723], [10, 0, 1040131328], [2, 0, 3854135066], [2, 0, 4133925041], [2, 0, 1738396966], [2, 12, 12], [8, 0, 550277338], [10, 0, 1043160697], [2, 1, 1176768057], [10, 1, 2368952475], [8, 12, 11], [2, 1, 2826144967], [8, 1, 1275301297], [10, 1, 2955899422], [2, 1, 2241699318], [12, 11, 10], [8, 1, 537794314], [11, 13, 10], [8, 1, 473021534], [17, 12, 13], [8, 1, 2381227371], [10, 1, 3973380876], [10, 1, 1728990628], [6, 11, 13], [8, 1, 2974252696], [0, 11, 11], [8, 1, 1912236055], [2, 1, 3620744853], [3, 10, 13], [2, 1, 2628426447], [11, 13, 12], [10, 1, 486914414], [16, 11, 12], [10, 1, 1187047173], [14, 12, 11], [2, 2, 3103274804], [13, 10, 10], [8, 2, 3320200805], [8, 2, 3846589389], [1, 13, 13], [2, 2, 2724573159], [10, 2, 1483327425], [2, 2, 1957985324], [14, 13, 12], [10, 2, 1467602691], [8, 2, 3142557962], [2, 13, 12], [2, 2, 2525769395], [8, 2, 3681119483], [8, 12, 11], [10, 2, 1041439413], [10, 2, 1042206298], [2, 2, 527001246], [20, 10, 13], [10, 2, 855860613], [8, 10, 10], [8, 2, 1865979270], [1, 13, 10], [8, 2, 2752636085], [2, 2, 1389650363], [10, 2, 2721642985], [18, 10, 11], [8, 2, 3276518041], [15, 10, 10], [2, 2, 1965130376], [2, 3, 3557111558], [2, 3, 3031574352], [16, 12, 10], [10, 3, 4226755821], [8, 3, 2624879637], [8, 3, 1381275708], [2, 3, 3310620882], [2, 3, 2475591380], [8, 3, 405408383], [2, 3, 2291319543], [0, 12, 12], [8, 3, 4144538489], [2, 3, 3878256896], [6, 11, 10], [10, 3, 2243529248], [10, 3, 561931268], [11, 11, 12], [10, 3, 3076955709], [18, 12, 13], [8, 3, 2019584073], [10, 13, 12], [8, 3, 1712479912], [18, 11, 11], [2, 3, 2804447380], [17, 10, 10], [10, 3, 2957126100], [18, 13, 13], [8, 3, 1368187437], [17, 10, 12], [8, 3, 3586129298], [10, 4, 1229526732], [19, 11, 11], [10, 4, 2759768797], [1, 10, 13], [2, 4, 2112449396], [10, 4, 1212917601], [2, 4, 1524771736], [8, 4, 3146530277], [2, 4, 2997906889], [16, 12, 10], [8, 4, 4135691751], [8, 4, 1960868242], [6, 12, 12], [10, 4, 2775657353], [16, 10, 13], [8, 4, 1451259226], [8, 4, 607382171], [13, 13, 13], [10, 4, 357643050], [2, 4, 2020402776], [8, 5, 2408165152], [13, 12, 10], [2, 5, 806913563], [10, 5, 772591592], [20, 13, 11], [2, 5, 2211018781], [10, 5, 2523354879], [8, 5, 2549720391], [2, 5, 3908178996], [2, 5, 1299171929], [8, 5, 512513885], [10, 5, 2617924552], [1, 12, 13], [8, 5, 390960442], [12, 11, 13], [8, 5, 1248271133], [8, 5, 2114382155], [1, 10, 13], [10, 5, 2078863299], [20, 12, 12], [8, 5, 2857504053], [10, 5, 4271947727], [2, 6, 2238126367], [2, 6, 1544827193], [8, 6, 4094800187], [2, 6, 3461906189], [10, 6, 1812592759], [2, 6, 1506702473], [8, 6, 536175198], [2, 6, 1303821297], [8, 6, 715409343], [2, 6, 4094566992], [14, 10, 11], [2, 6, 1890141105], [0, 13, 13], [2, 6, 3143319360], [10, 7, 696930856], [2, 7, 926450200], [8, 7, 352056373], [20, 13, 11], [10, 7, 3857703071], [8, 7, 3212660135], [5, 12, 10], [10, 7, 3854876250], [21, 12, 11], [8, 7, 3648688720], [2, 7, 2732629817], [4, 10, 12], [10, 7, 2285138643], [18, 10, 13], [2, 7, 2255852466], [2, 7, 2537336944], [3, 10, 13], [2, 7, 4257606405], [10, 8, 3703184638], [7, 11, 10], [10, 8, 2165056562], [8, 8, 2217220568], [19, 10, 12], [8, 8, 2088084496], [15, 13, 10], [8, 8, 443074220], [16, 13, 12], [10, 8, 1298336973], [2, 13, 11], [8, 8, 822378456], [19, 11, 12], [8, 8, 2154711985], [0, 11, 12], [10, 8, 430757325], [2, 12, 10], [2, 8, 2521672196], [10, 9, 532704100], [10, 9, 2519542932], [2, 9, 2451309277], [2, 9, 3957445476], [5, 10, 10], [8, 9, 2583554449], [10, 9, 1149665327], [12, 13, 12], [8, 9, 3053959226], [0, 10, 10], [8, 9, 3693780276], [15, 11, 10], [2, 9, 609918789], [2, 9, 2778221635], [16, 13, 10], [8, 9, 3133754553], [8, 11, 13], [8, 9, 3961507338], [2, 9, 1829237263], [16, 11, 13], [2, 9, 2472519933], [6, 12, 12], [8, 9, 4061630846], [10, 9, 1181684786], [13, 10, 11], [10, 9, 390349075], [8, 9, 2883917626], [10, 9, 3733394420], [10, 12, 12], [2, 9, 3895283827], [20, 10, 11], [2, 9, 2257053750], [10, 9, 2770821931], [18, 10, 13], [2, 9, 477834410], [19, 13, 12], [3, 0, 1], [12, 12, 12], [3, 1, 2], [11, 13, 11], [3, 2, 3], [3, 3, 4], [3, 4, 5], [1, 13, 13], [3, 5, 6], [7, 11, 11], [3, 6, 7], [4, 10, 12], [3, 7, 8], [18, 12, 12], [3, 8, 9], [21, 12, 10], [3, 9, 10]]

s = Solver()

R = [BitVec(f'REG{i}', 32) for i in range(15)]
target = [0x3ee88722, 0xecbdbe2, 0x60b843c4, 0x5da67c7, 0x171ef1e9, 0x52d5b3f7, 0x3ae718c0, 0x8b4aacc2, 0xe5cf78dd, 0x4a848edf, 0x8f, 0x4180000, 0x0, 0xd, 0x0]
flag = [BitVec(f'flag{i}', 32) for i in range(40)]
orig_flag = [c for c in flag]

for c in orig_flag:
    s.add(And(0x20 <= c,c <= 0x7f))

for opcode in opcodes:
    parse(*opcode)

for i in range(15):
    s.add(R[i] == target[i])

assert s.check() == sat

m = s.model()
print(''.join([chr(m[x].as_long()) for x in orig_flag]))
```

flag : `HTB{m4n_1_l0v4_cXX_TeMpl4t35_9fb60c17b0}`

### MazeOfPower - 350pts

solver 짜던 중에 팀원 분이 먼저 풀어서 나중에 다시 풀었다..ㅎ

`main`이 주어지고 remote로 풀어야 한다.

```shell
$ file main
main: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=246eec7fd33acbeba185edfe290af7cb632dec84, for GNU/Linux 3.2.0, with debug_info, not stripped
```

#### main

```c
// main.main
// local variable allocation has failed, the output may be wrong!
void __fastcall main_main()
{
  __int128 v0; // xmm15
  __int64 v1; // rax
  __int64 v2; // rbx
  __int64 v3; // rbp
  void *v4; // rax
  __int64 v5; // rbp
  __int64 v6; // rax
  int v7; // rcx OVERLAPPED
  _slice_int *v8; // rdx
  int v9; // rbx
  int *v10; // rax
  _slice_int *v11; // rax
  __int64 v12; // rsi
  int **v13; // r11
  maze_Point *p_maze_Point; // rax
  maze_Point *v15; // rax
  uint8 *str; // rax
  char v17; // dl
  int i; // rax
  uint8 *v19; // rax
  main_keyDir *v20; // r9
  __int64 *v21; // [rsp+0h] [rbp-310h]
  _BYTE v22[71]; // [rsp+10h] [rbp-300h] BYREF
  char v23[25]; // [rsp+57h] [rbp-2B9h] BYREF
  int oldCap; // [rsp+70h] [rbp-2A0h]
  const char *t; // [rsp+78h] [rbp-298h]
  time_Time v26; // [rsp+80h] [rbp-290h]
  _slice_int *v27; // [rsp+98h] [rbp-278h]
  github_com_redpwn_pow_Challenge *c; // [rsp+A0h] [rbp-270h]
  __m256 v29; // [rsp+A8h] [rbp-268h] BYREF
  __int128 v30; // [rsp+C8h] [rbp-248h] BYREF
  github_com_itchyny_maze_Format format; // [rsp+D8h] [rbp-238h] BYREF
  github_com_itchyny_maze_Maze maze; // [rsp+1E8h] [rbp-128h] BYREF
  __int128 v33; // [rsp+230h] [rbp-E0h] BYREF
  __int64 v34; // [rsp+240h] [rbp-D0h]
  RTYPE **v35; // [rsp+248h] [rbp-C8h]
  _ptr_os_File v36; // [rsp+250h] [rbp-C0h]
  __int64 v37; // [rsp+278h] [rbp-98h]
  __int64 v38; // [rsp+280h] [rbp-90h]
  bufio_Reader b; // [rsp+288h] [rbp-88h] BYREF
  _slice_interface_ a; // [rsp+2E0h] [rbp-30h] BYREF
  int *v41; // [rsp+2F8h] [rbp-18h]
  _ptr_os_File v42; // [rsp+300h] [rbp-10h]
  __int64 v43; // [rsp+308h] [rbp-8h] BYREF
  _slice_interface_ v44; // 0:rsi.24
  io_Writer v45; // 0:rax.8,8:rbx.8
  string v46; // 0:rax.8,8:rbx.8
  string v47; // 0:rax.8,8:rbx.8
  string v48; // 0:rax.8,8:rbx.8
  string v49; // 0:rcx.8,8:rdi.8 OVERLAPPED
  _slice_interface_ v50; // 0:rcx.8,8:rdi.16
  _slice_interface_ v51; // 0:rcx.8,8:rdi.16
  _slice_interface_ v52; // 0:rcx.8,8:rdi.16
  string v53; // 0:rbx.8,8:rcx.8
  string pow_str; // 0:rbx.8,8:rcx.8
  string v55; // 0:rbx.8,8:rcx.8
  string v56; // 0:rbx.8,8:rcx.8
  retval_4B59E0 v57; // 0:al.1,8:rbx.8,16:rcx.8
  _slice_uint8 pow; // 0:rax.8,8:rbx.8,16:rcx.8
  time_Time v59; // 0:rax.8,8:rbx.8,16:rcx.8
  time_Time v60; // 0:rax.8,8:rbx.8,16:rcx.8
  _slice_uint8_0 v61; // 0:rbx.8,8:rcx.8,16:rdi.8 OVERLAPPED

  c = github_com_redpwn_pow_GenerateChallenge(0x1388u);
  a.array = (interface_ *)&RTYPE__ptr_pow_Challenge;
  a.len = (int)c;
  v45.data = os_Stdout;
  v49.str = (uint8 *)"proof of work: curl -sSfL https://pwn.red/pow | sh -s %s\nsolution";
  v49.len = 67LL;
  v44.array = (interface_ *)&a;
  v44.len = 1LL;
  v44.cap = 1LL;
  v45.tab = (runtime_itab *)&go_itab__ptr_os_File_comma_io_Writer;
  *(retval_4957E0 *)&v49.str = fmt_Fprintf(v45, v49, v44);
  v42 = os_Stdin;
  *(_OWORD *)&b.buf.array = v0;
  v21 = &v43;
  ((void (__golang *)(__int64, __int64, _ptr_os_File, _BYTE *))loc_46AEF0)(v1, v2, os_Stdin, &v22[592]);
  v3 = (__int64)v21;
  v4 = runtime_makeslice((internal_abi_Type *)&RTYPE_uint8_0, 4096LL, 4096LL);
  v33 = v0;
  v21 = (__int64 *)v3;
  *(_QWORD *)&v33 = ((__int64 (__golang *)(void *, __int64, uint8 *, _BYTE *))loc_46AEF0)(
                      v4,
                      4096LL,
                      v49.str,
                      &v22[504]);
  *((_QWORD *)&v33 + 1) = 4096LL;
  v34 = 4096LL;
  v35 = go_itab__ptr_os_File_comma_io_Reader;
  v36 = v42;
  v37 = -1LL;
  v38 = -1LL;
  b.buf.array = (uint8 *)v33;
  ((void (__fastcall *)(int *, char *))loc_46B25A)(&b.buf.len, (char *)&v33 + 8);
  v5 = (__int64)v21;
  v26.loc = (time_Location *)bufio__ptr_Reader_ReadString(&b, 0xAu);
  *(_QWORD *)&v23[9] = 10LL;
  v53.len = 10LL;
  v53.str = (uint8 *)v26.loc;
  v57 = github_com_redpwn_pow__ptr_Challenge_Check(c, v53);
  if ( !v57._r1.tab && v57._r0 )
  {
    pow_str.str = (uint8 *)v26.loc;
    pow_str.len = *(_QWORD *)&v23[9];
    pow = runtime_stringtoslicebyte(0LL, pow_str);
    LODWORD(pow.array) = hash_crc32_ChecksumIEEE(pow);
    math_rand_Seed(LODWORD(pow.array));
    v6 = 0LL;
    v7 = 0LL;
    v8 = 0LL;
    v9 = 0LL;
    while ( v6 < 25 )
    {
      *(_QWORD *)&v23[1] = v6;
      oldCap = v7;
      v27 = v8;
      *(_QWORD *)&v23[17] = v9;
      v10 = (int *)runtime_makeslice((internal_abi_Type *)&RTYPE_int_0, 50LL, 50LL);
      v9 = *(_QWORD *)&v23[17] + 1LL;
      v7 = oldCap;
      if ( oldCap < (unsigned __int64)(*(_QWORD *)&v23[17] + 1LL) )
      {
        v41 = v10;
        *(runtime_slice *)(&v7 - 2) = runtime_growslice(v27, v9, oldCap, 1LL, (internal_abi_Type *)&RTYPE__slice_int_0);
        v8 = v11;
        v10 = v41;
      }
      else
      {
        v8 = v27;
      }
      v12 = v9;
      v8[v12 - 1].len = 50LL;
      v8[v12 - 1].cap = 50LL;
      if ( *(_DWORD *)&runtime_writeBarrier.enabled )
      {
        runtime_gcWriteBarrier2();
        *v13 = v10;
        v13[1] = v8[v9 - 1].array;
      }
      v8[v9 - 1].array = v10;
      v6 = *(_QWORD *)&v23[1] + 1LL;
    }
    *(_OWORD *)&maze.Start = v0;
    *(_OWORD *)&maze.Cursor = v0;
    maze.Directions.len = v9;
    maze.Directions.cap = v7;
    maze.Directions.array = v8;
    maze.Height = 25LL;
    maze.Width = 50LL;
    maze.Start = (github_com_itchyny_maze_Point *)runtime_newobject((internal_abi_Type *)&RTYPE_maze_Point);
    p_maze_Point = (maze_Point *)runtime_newobject((internal_abi_Type *)&RTYPE_maze_Point);
    p_maze_Point->X = 24LL;
    p_maze_Point->Y = 49LL;
    maze.Goal = (github_com_itchyny_maze_Point *)p_maze_Point;
    maze.Cursor = (github_com_itchyny_maze_Point *)runtime_newobject((internal_abi_Type *)&RTYPE_maze_Point);
    maze.Solved = 0;
    maze.Started = 0;
    maze.Finished = 0;
    maze.Start = (github_com_itchyny_maze_Point *)runtime_newobject((internal_abi_Type *)&RTYPE_maze_Point);
    v15 = (maze_Point *)runtime_newobject((internal_abi_Type *)&RTYPE_maze_Point);
    v15->X = maze.Height - 1;
    v15->Y = maze.Width - 1;
    maze.Goal = (github_com_itchyny_maze_Point *)v15;
    maze.Cursor = maze.Start;
    github_com_itchyny_maze__ptr_Maze_Generate(&maze);
    v21 = (__int64 *)v5;
    ((void (__fastcall *)(_BYTE *))loc_46AEAB)(&v22[152]);
    format.Wall.len = 2LL;
    format.Wall.str = (uint8 *)"  "; // 벽 안 보임
    format.Path.len = 2LL;
    format.Path.str = (uint8 *)"  ";
    format.StartLeft.len = 2LL;
    format.StartLeft.str = (uint8 *)"SS";
    format.StartRight.len = 2LL;
    format.StartRight.str = (uint8 *)"SS";
    format.GoalLeft.len = 2LL;
    format.GoalLeft.str = (uint8 *)"EE";
    format.GoalRight.len = 2LL;
    format.GoalRight.str = (uint8 *)"EE";
    format.Solution.len = 2LL;
    format.Solution.str = (uint8 *)"::";
    format.SolutionStartLeft.len = 2LL;
    format.SolutionStartLeft.str = (uint8 *)"SS";
    format.SolutionStartRight.len = 2LL;
    format.SolutionStartRight.str = (uint8 *)"SS";
    format.SolutionGoalLeft.len = 2LL;
    format.SolutionGoalLeft.str = (uint8 *)"EE";
    format.SolutionGoalRight.len = 2LL;
    format.SolutionGoalRight.str = (uint8 *)"EE";
    format.Visited.len = 2LL;
    format.Visited.str = (uint8 *)"  ";
    format.VisitedStartLeft.len = 2LL;
    format.VisitedStartLeft.str = (uint8 *)"SS";
    format.VisitedStartRight.len = 2LL;
    format.VisitedStartRight.str = (uint8 *)"SS";
    format.VisitedGoalLeft.len = 2LL;
    format.VisitedGoalLeft.str = (uint8 *)"EE";
    format.VisitedGoalRight.len = 2LL;
    format.VisitedGoalRight.str = (uint8 *)"EE";
    format.Cursor.len = 2LL;
    format.Cursor.str = (uint8 *)"::";
    v26.ext = (int64)time_NewTicker(10000000LL);
    v59 = time_Now();
    v26.wall = v59.wall;
    t = "EE";
    a.cap = (int)v59.loc;
    maze.Started = 1;
    str = github_com_itchyny_maze__ptr_Maze_String(&maze, &format).str;
    v30 = v0;
    v55.len = 61LL;
    v50.len = (int)str;
    v50.cap = (int)&format;
    v55.str = (uint8 *)"Can you solve my maze within 20 seconds?\nControls: q/k/j/h/l\n";
    v46 = runtime_concatstring2(0LL, v55, *(string *)&v50.len);
    v46.str = (uint8 *)runtime_convTstring(v46);
    *(_QWORD *)&v30 = &RTYPE_string_0;
    *((_QWORD *)&v30 + 1) = v46.str;
    v46.len = (int)os_Stdout;
    v46.str = (uint8 *)&go_itab__ptr_os_File_comma_io_Writer;
    v50.len = 1LL;
    v50.cap = 1LL;
    v50.array = (interface_ *)&v30;
    fmt_Fprintln((io_Writer)v46, v50);
    while ( 1 )
    {
      do
      {
LABEL_13:
        v23[0] = 0;
        v61.ptr = (uint8_0 *)v23;
        v61.len = 1LL;
        v61.cap = 1LL;
        v61 = (_slice_uint8_0)os__ptr_File_Read(os_Stdin, v61);
      }
      while ( v61.ptr );
      v17 = v23[0];
      if ( (unsigned __int8)(v23[0] - 'A') <= 0x19u )
        v17 = v23[0] + ' ';
      if ( !maze.Finished )
      {
        for ( i = 0LL; i < main_keyDirs.len; ++i )
        {
          v20 = main_keyDirs.array[i];
          if ( v20->char == v17 )
          {
            github_com_itchyny_maze__ptr_Maze_Move(&maze, v20->dir);
            if ( maze.Finished )
              github_com_itchyny_maze__ptr_Maze_Solve(&maze);
            v19 = github_com_itchyny_maze__ptr_Maze_String(&maze, &format).str;
            *(_OWORD *)&v29.m256_f32[4] = v0;
            v56.len = 61LL;
            v51.len = (int)v19;
            v51.cap = (int)&format;
            v56.str = (uint8 *)"Can you solve my maze within 20 seconds?\nControls: q/k/j/h/l\n";
            v47 = runtime_concatstring2(0LL, v56, *(string *)&v51.len);
            v47.str = (uint8 *)runtime_convTstring(v47);
            *(_QWORD *)&v29.m256_f32[4] = &RTYPE_string_0;
            *(_QWORD *)&v29.m256_f32[6] = v47.str;
            v47.len = (int)os_Stdout;
            v47.str = (uint8 *)&go_itab__ptr_os_File_comma_io_Writer;
            v51.len = 1LL;
            v51.cap = 1LL;
            v51.array = (interface_ *)&v29.m256_f32[4];
            fmt_Fprintln((io_Writer)v47, v51);
            if ( maze.Finished )
            {
              v60.wall = v26.wall;
              v60.ext = (int64)t;
              v60.loc = (time_Location *)a.cap;
              v60.wall = time_Since(v60);
              main_printFinished(&maze, v60.wall); // prints flag
            }
            goto LABEL_13;
          }
        }
      }
      if ( v17 == 'q' )
        break;
      if ( v17 == 'b' )
      {
        github_com_itchyny_maze__ptr_Maze_Solve(&maze);
        maze.Finished = 1;
        v48 = github_com_itchyny_maze__ptr_Maze_String(&maze, &format);
        *(_OWORD *)v29.m256_f32 = v0;
        v48.str = (uint8 *)runtime_convTstring(v48);
        *(_QWORD *)v29.m256_f32 = &RTYPE_string_0;
        *(_QWORD *)&v29.m256_f32[2] = v48.str;
        v48.len = (int)os_Stdout;
        v48.str = (uint8 *)&go_itab__ptr_os_File_comma_io_Writer;
        v52.len = 1LL;
        v52.cap = 1LL;
        v52.array = (interface_ *)&v29;
        fmt_Fprintln((io_Writer)v48, v52);
      }
    }
    time_stopTimer((runtime_timer *)(v26.ext + 8));
  }
}
```

[https://github.com/itchyny/maze/blob/main/maze.go](https://github.com/itchyny/maze/blob/main/maze.go)를 사용한다.

분석해보면 `k`, `j`, `h`, `l`이 방향키고 20초 안에 미로를 통과하면 flag를 출력한다.

`b`를 누르면 maze의 solution이 출력되지만 `maze.Finished = 1`로 설정돼서 

```c
if ( maze.Finished )
{
    v60.wall = v26.wall;
    v60.ext = (int64)t;
    v60.loc = (time_Location *)a.cap;
    v60.wall = time_Since(v60);
    main_printFinished(&maze, v60.wall); // prints flag
}
```

여기 있는 flag 출력 로직으로 갈 수가 없다.

#### solution

`main`에서 보면

```c
v53.str = (uint8 *)v26.loc;
v57 = github_com_redpwn_pow__ptr_Challenge_Check(c, v53);
if ( !v57._r1.tab && v57._r0 )
{
    v54.str = (uint8 *)v26.loc;
    v54.len = *(_QWORD *)&v23[9];
    v58 = runtime_stringtoslicebyte(0LL, v54);
    LODWORD(v58.array) = hash_crc32_ChecksumIEEE(v58);
    math_rand_Seed(LODWORD(v58.array));
    ...
```

`crc32(PoW)`를 seed로 사용한다.

github 코드를 보면 `math/rand`를 이용해 random한 maze를 생성하기 때문에 PoW 값으로 remote 환경의 maze를 얻을 수 있다.

[https://github.com/itchyny/maze/blob/main/maze.go#L141](https://github.com/itchyny/maze/blob/main/maze.go#L141)로 maze의 solution을 얻을 수 있어서 아래 코드를 작성했다.

#### get_maze.go

```go
package main

import (
    "fmt"
    "hash/crc32"
    "math/rand"
    "github.com/itchyny/maze"
)

func main() {
    var input string
    fmt.Scanln(&input) // PoW 입력
    input += "\n"
    inputBytes := []byte(input)

    hash := crc32.ChecksumIEEE(inputBytes)
    rand.Seed(int64(hash))

    m := maze.NewMaze(25, 50)
    m.Generate()
    m.Solve()
    fmt.Println(m.String(maze.Default))
}
```

이제 maze의 solution을 얻을 수 있으니 서버로 path를 보내주는 코드만 작성하면 된다.

#### sol.py

```python
'''
h : left
j : down
k : up
l : right
q : quit
b : solve -> prints answer. if once it called, cannot get flag
if ( !maze.Finished ) // blocked here
      {
        for ( i = 0LL; i < main_keyDirs.len; ++i )
'''

import subprocess
from pwn import *

def solve(PoW):
    r = process(['go', 'run', '.'])
    r.sendline(PoW)
    lines = r.recvall().decode().split('\n')[2:-4]

    maze = [[] for _ in range(len(lines))]
    for i, line in enumerate(lines):
        for j in range(2, len(line), 2):
            maze[i].append(line[j:j+2])

    dx = [1, 0, -1, 0]
    dy = [0, 1, 0, -1]
    dd = ['l', 'j', 'h', 'k']

    cur = [0, 1] # y, x
    path = []
    while 1:
        if cur == [48, 99]:
            break

        for i in range(4):
            nx = cur[1] + dx[i]
            ny = cur[0] + dy[i]

            if nx < 0 or nx >= 100 or ny < 0 or ny >= 49:
                continue

            if maze[ny][nx] != '::':
                continue

            path.append(dd[i])
            maze[ny][nx] = '  '
            nx += dx[i]
            ny += dy[i]
            maze[ny][nx] = '  '
            cur = [ny, nx]
            break

    return path


# p = process('./main')
p = remote('83.136.249.138', 33145)

result = subprocess.run(p.recvlineS().split("proof of work:")[1], shell=True, capture_output=True, text=True)
p.sendlineafter('solution:', result.stdout)

ans = solve(result.stdout)
p.sendline(''.join(ans))

p.interactive()
```

![](/assets/img/2024/20240320_mazeofpower.png)

flag : `HTB{by_th3_p0w3r_0f_th3_m4z3!!1}`

리모트로 풀어야 돼서 전혀 생각도 안 했는데 팀원은 코드 패치해서 풀었다.

PoW 확인하는 부분만 패치하면 `b`로 solution을 얻을 수 있어서 훨씬 편하다..

### 후기

학교 다니느라 평일에 많이 못 참여할까봐 걱정했는데

걱정이 무색하게 팀원들이 15시간만에 올클해버렸다 :joy:

이번에 연합팀으로 해보니 숙련도 차이로 리버싱이나 코드 작성할 때 잘하는 사람들이랑 시간 차이가 많이 나는 거 같다.

앞으로 리버싱 많이 해야겠다..!
