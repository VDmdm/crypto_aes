package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
)

const (
	/*  число столбцов (32-битных слов), составляющих State */
	NB = 4

	/* число 32-битных слов, составляющих шифроключ */
	/* для 128 - 10 */
	/* для 192 - 12 */
	/* для 256 - 14 */

	AES_128_NR = 10
	AES_192_NR = 12
	AES_256_NR = 14

	/* число раундов в зависимости от длины ключа */
	/* для 128 - 4 */
	/* для 192 - 6 */
	/* для 256 - 8 */

	AES_128_NK = 4
	AES_192_NK = 6
	AES_256_NK = 8
)

/* таблица подстановок, The Rijndael S-box */
/* является константой в Rijndael алгоритме */
/* может быть вычислена, но смысла не имеет, добавит только бесполезную нагрузку */
var SBOX = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

/* обратная таблица подстановок, используемая при расшифровании */
var INVSBOX = [256]byte{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
}

/* предварительно рассчитанные раундовые константы */
/* используется при выработке раундовых ключей */
/* является константой в Rijndael алгоритме */

var RCON = [16]byte{
	0x00, 0x01, 0x02, 0x04,
	0x08, 0x10, 0x20, 0x40,
	0x80, 0x1b, 0x36, 0x6c,
	0xd8, 0xab, 0x4d, 0x9a,
}

/*  Матрица смешивания для MixColumns. */
/*  Для зашифрования. */
/*  Является константой в Rijndael алгоритме */

var MIXCOLUMNSCOEFFICIENTS = [16]byte{
	0x02, 0x03, 0x01, 0x01,
	0x01, 0x02, 0x03, 0x01,
	0x01, 0x01, 0x02, 0x03,
	0x03, 0x01, 0x01, 0x02,
}

/*  Обратная матрица смешивания для MixColumns. */
/*  Для расшифрования. */
/*  Является константой в Rijndael алгоритме */

var INVMIXCOLUMNSCOEFFICIENTS = [16]byte{
	0x0e, 0x0b, 0x0d, 0x09,
	0x09, 0x0e, 0x0b, 0x0d,
	0x0d, 0x09, 0x0e, 0x0b,
	0x0b, 0x0d, 0x09, 0x0e,
}

/*  Функция замены байт в в ключе с использованием таблицы подстановок SBOX */
func subWord(word [4]byte) [4]byte {
	word[0], word[1], word[2], word[3] = SBOX[int(word[0])], SBOX[int(word[1])], SBOX[int(word[2])], SBOX[int(word[3])]
	return word
}

/* Функция циклической перестановки байт в процедуре KeyExpansion */
/* круговой сдвиг влево */
func rotWord(word [4]byte) [4]byte {
	word[0], word[1], word[2], word[3] = word[1], word[2], word[3], word[0]
	return word
}

/* Функция xor с раудновыми константами в процедуре KeyExpansion */
func xorRcon(word [4]byte, rcon_idx int) [4]byte {
	word[0], word[1], word[2], word[3] = word[0]^RCON[rcon_idx], word[1]^RCON[rcon_idx], word[2]^RCON[rcon_idx], word[3]^RCON[rcon_idx]
	return word
}

/* Процедура выработки раундовых ключей */
func keyExpansion(key []byte, roundKey []byte, nk int, nr int) {
	var tmp [4]byte

	// заполнение первых nk блоков раундовых ключей значениями из key
	for i := 0; i < nk; i++ {
		roundKey[i*4], roundKey[i*4+1], roundKey[i*4+2], roundKey[i*4+3] = key[i*4], key[i*4+1], key[i*4+2], key[i*4+3]
	}

	// заполнение оставшихся блоков
	// i от nk (до nk мы заполнили выше)
	// i до количества блоков * на количество раундов в зависимости от длины ключа включительно (из-за +1)
	for i := nk; i < (NB * (nr)); i++ {
		tmp[0], tmp[1], tmp[2], tmp[3] = roundKey[(i-1)*4], roundKey[(i-1)*4+1], roundKey[(i-1)*4+2], roundKey[(i-1)*4+3]
		if i%nk == 0 {
			tmp = xorRcon(subWord(rotWord(tmp)), i/nk)
		} else if nk == 8 && i%nk == 4 {
			tmp = subWord(tmp)
		}
		roundKey[i*4+0] = roundKey[(i-nk)*4+0] ^ tmp[0]
		roundKey[i*4+1] = roundKey[(i-nk)*4+1] ^ tmp[1]
		roundKey[i*4+2] = roundKey[(i-nk)*4+2] ^ tmp[2]
		roundKey[i*4+3] = roundKey[(i-nk)*4+3] ^ tmp[3]
	}
}

/* Процедура сложения state с соответствующим раундовым ключом */
func addRoundKey(round int, state [][]byte, roundKey []byte) {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[j][i] ^= roundKey[(i*NB+j)+(round*NB*4)]
		}
	}
}

/* Процедура замены каждого байта state соответствующим значением из SBOX */
/*  Для зашифрования. */
func subBytes(state [][]byte) {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[i][j] = SBOX[state[i][j]]
		}
	}
}

/*  Процедура обратной замены каждого байта state соответствующим значением из SBOX */
/*  Для расшифрования. */
func invSubBytes(state [][]byte) {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[i][j] = INVSBOX[state[i][j]]
		}
	}
}

/*  Процедура кругового сдвига state */
/*  Для зашфирования. */
func shiftRows(state [][]byte) {
	// Первая строка остаётся без изменений.
	// Круговой сдвиг второй строки на 1 влево.
	state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]

	// Круговой сдвиг третьей строки на 2 влево.
	state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]

	// Круговой сдвиг четвертой строки на 3 влево.
	state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]
}

/*  Процедура обратного кругового сдвига state */
/*  Для расшифрования. */
func invShiftRows(state [][]byte) {
	// Первая строка остаётся без изменений.
	// Круговой сдвиг второй строки на 1 вправо.
	state[1][3], state[1][2], state[1][1], state[1][0] = state[1][2], state[1][1], state[1][0], state[1][3]

	// Круговой сдвиг третьей строки на 2 вправо.
	state[2][3], state[2][2], state[2][1], state[2][0] = state[2][1], state[2][0], state[2][3], state[2][2]

	// Круговой сдвиг четвертой строки на 3 вправо.
	state[3][3], state[3][2], state[3][1], state[3][0] = state[3][0], state[3][3], state[3][2], state[3][1]
}

/*  Функция умножения в поле GF(2^8) */
func gMul(x, y byte) byte {
	r := byte(0)
	hi_bit := byte(0)

	// итерируемся 8 раз по каждому биту
	for bit := 8; bit > 0; bit-- {
		// если текущий бит y равен 1, прибавляем к результату
		if y&1 != 0 {
			r ^= x
		}

		// определяем текущий старший бит у числа в x и запоминаем его
		hi_bit = x & 0x80 // 10000000

		//сдвигаем x на 1 бит влево
		x <<= 1

		// если старший бит равен 1
		if hi_bit != 0 {
			x ^= 0x1b //11011
		}

		//сдвигаем y на 1 бит вправо
		y >>= 1
	}
	return r
}

/*  Процедура смешивания столбцов state */
/*  Для зашифрования. */
func mixColumns(state [][]byte) {
	// Создаем временную матрицу, чтобы запомнить исходное состояние
	tmp := make([][]byte, 4)
	for i := range state {
		tmp[i] = make([]byte, 4)
		copy(tmp[i], state[i])
	}

	for i := 0; i < 4; i++ {
		// Умножаем каждый элемент столбца на соответствующий элемент матрицы смешивания и xor'им
		state[0][i] = gMul(MIXCOLUMNSCOEFFICIENTS[0], tmp[0][i]) ^ gMul(MIXCOLUMNSCOEFFICIENTS[1], tmp[1][i]) ^ gMul(MIXCOLUMNSCOEFFICIENTS[2], tmp[2][i]) ^ gMul(MIXCOLUMNSCOEFFICIENTS[3], tmp[3][i])
		state[1][i] = gMul(MIXCOLUMNSCOEFFICIENTS[4], tmp[0][i]) ^ gMul(MIXCOLUMNSCOEFFICIENTS[5], tmp[1][i]) ^ gMul(MIXCOLUMNSCOEFFICIENTS[6], tmp[2][i]) ^ gMul(MIXCOLUMNSCOEFFICIENTS[7], tmp[3][i])
		state[2][i] = gMul(MIXCOLUMNSCOEFFICIENTS[8], tmp[0][i]) ^ gMul(MIXCOLUMNSCOEFFICIENTS[9], tmp[1][i]) ^ gMul(MIXCOLUMNSCOEFFICIENTS[10], tmp[2][i]) ^ gMul(MIXCOLUMNSCOEFFICIENTS[11], tmp[3][i])
		state[3][i] = gMul(MIXCOLUMNSCOEFFICIENTS[12], tmp[0][i]) ^ gMul(MIXCOLUMNSCOEFFICIENTS[13], tmp[1][i]) ^ gMul(MIXCOLUMNSCOEFFICIENTS[14], tmp[2][i]) ^ gMul(MIXCOLUMNSCOEFFICIENTS[15], tmp[3][i])
	}

}

/*  Обратная процедура смешивания столбцов state */
/*  Для расшифрования. */
func invMixColumns(state [][]byte) {
	// Создаем временную матрицу, чтобы запомнить исходное состояние
	tmp := make([][]byte, 4)
	for i := range state {
		tmp[i] = make([]byte, 4)
		copy(tmp[i], state[i])
	}

	for i := 0; i < 4; i++ {
		// Умножаем каждый элемент столбца на соответствующий элемент матрицы смешивания и xor'им
		state[0][i] = gMul(tmp[0][i], INVMIXCOLUMNSCOEFFICIENTS[0]) ^ gMul(tmp[1][i], INVMIXCOLUMNSCOEFFICIENTS[1]) ^ gMul(tmp[2][i], INVMIXCOLUMNSCOEFFICIENTS[2]) ^ gMul(tmp[3][i], INVMIXCOLUMNSCOEFFICIENTS[3])
		state[1][i] = gMul(tmp[0][i], INVMIXCOLUMNSCOEFFICIENTS[4]) ^ gMul(tmp[1][i], INVMIXCOLUMNSCOEFFICIENTS[5]) ^ gMul(tmp[2][i], INVMIXCOLUMNSCOEFFICIENTS[6]) ^ gMul(tmp[3][i], INVMIXCOLUMNSCOEFFICIENTS[7])
		state[2][i] = gMul(tmp[0][i], INVMIXCOLUMNSCOEFFICIENTS[8]) ^ gMul(tmp[1][i], INVMIXCOLUMNSCOEFFICIENTS[9]) ^ gMul(tmp[2][i], INVMIXCOLUMNSCOEFFICIENTS[10]) ^ gMul(tmp[3][i], INVMIXCOLUMNSCOEFFICIENTS[11])
		state[3][i] = gMul(tmp[0][i], INVMIXCOLUMNSCOEFFICIENTS[12]) ^ gMul(tmp[1][i], INVMIXCOLUMNSCOEFFICIENTS[13]) ^ gMul(tmp[2][i], INVMIXCOLUMNSCOEFFICIENTS[14]) ^ gMul(tmp[3][i], INVMIXCOLUMNSCOEFFICIENTS[15])
	}
}

/*  Процедура зашифрования блока исходного текста*/
func encryptBlock(in []byte, roundKey []byte, nr int, out []byte) {
	// создание state
	state := make([][]byte, 4)
	for i := range state {
		state[i] = make([]byte, 4)
	}

	// заполнение state значениями из входящего блока текста
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[j][i] = in[i*4+j]
		}
	}

	// для первого раунда производится только процедура добавления раундового ключа
	addRoundKey(0, state, roundKey)
	for round := 1; round < nr; round++ {
		// раунд процедуры зашифрования
		// Процедура замены каждого байта state соответствующим значением из SBOX
		subBytes(state)
		// Процедура кругового сдвига state
		shiftRows(state)
		// Процедура смешивания столбцов state
		mixColumns(state)
		// Процедура сложения state с соответствующим раундовым ключом
		addRoundKey(round, state, roundKey)
	}

	// Последений раунд
	// Для последнего раунда процедура смешивания не выполняется
	subBytes(state)
	shiftRows(state)
	addRoundKey(nr, state, roundKey)

	// запись итогового state в выходную строку
	// из матрицы 4х4 в строку (вектор)
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			out[i*4+j] = state[j][i]
		}
	}
}

/*  Процедура расшифрования блока шифртекста*/
func decryptBlock(in []byte, roundKey []byte, nr int, out []byte) {
	// создание state
	state := make([][]byte, 4)
	for i := range state {
		state[i] = make([]byte, 4)
	}

	// заполнение state значениями из входящего блока текста
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[j][i] = in[i*4+j]
		}
	}

	// для первого раунда производится только процедура добавления раундового ключа
	addRoundKey(nr, state, roundKey)

	for round := nr - 1; round > 0; round-- {
		// раунд процедуры расшифрования
		// Процедура обратного кругового сдвига state
		invShiftRows(state)
		// Процедура обратной замены каждого байта state соответствующим значением из SBOX
		invSubBytes(state)
		// Процедура сложения state с соответствующим раундовым ключом
		addRoundKey(round, state, roundKey)
		// Обратная процедура смешивания столбцов state
		invMixColumns(state)
	}

	// Последений раунд
	// Для последнего раунда процедура смешивания не выполняется
	invShiftRows(state)
	invSubBytes(state)
	addRoundKey(0, state, roundKey)

	// запись итогового state в выходную строку
	// из матрицы 4х4 в строку (вектор)
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			out[i*4+j] = state[j][i]
		}
	}
}

// Вспомогательная процедура для выполнения xor двух slice
func xorSlice(in []byte, out []byte) {
	for i := range in {
		out[i] ^= in[i]
	}
}

// Процедура зашифрования в режиме cbc (Режим сцепления блоков шифротекста)
func aesEncCbc(in []byte, roundKey []byte, nk int, nr int, iv []byte) []byte {
	// Создание буферов для промежуточных значений
	var out_buf []byte
	in_buf, iv_buf := make([]byte, 16), make([]byte, 16)
	out := make([]byte, 0)

	// Копирование значение вектора инициализации (синхропосылка)
	copy(iv_buf[:], iv[:])

	// итерация по блокам входящей строки (блоки по 16 байт или 128 бит)
	// i увеличивается на блок 16 байт
	for i := 0; i < len(in); i += 16 {
		// копирование блока 16 байт исходной строки в буфер
		copy(in_buf[:], in[i:i+16])
		// сложение блока исходного текста со значением в буфере вектора инициализации (синхропосылки)
		// для первого раунда это значение вектора инициализации переданного аргументом функции
		// для последующих раундов это предыдущее выходное значение функции зашифрования
		xorSlice(iv_buf, in_buf)
		// применение функции зашифрования с простой заменой (ecb) c записью в буфер выходных значений
		out_buf = aesEncEcb(in_buf, roundKey, nk, nr)
		// запись получившихся значений из буфера в выходную строку
		out = append(out, out_buf...)
		// копирование текущего итога зашифрования в буфер вектора инициализации (с заменой)
		copy(iv_buf[:], out_buf)
	}

	// возврат итоговой строки
	return out
}

// Процедура расшифрования в режиме cbc (Режим сцепления блоков шифротекста)
func aesDecCbc(in []byte, roundKey []byte, nk int, nr int, iv []byte) []byte {
	// Создание буферов для промежуточных значений
	var out_buf []byte
	in_buf, iv_buf := make([]byte, 16), make([]byte, 16)
	out := make([]byte, 0)

	// Копирование значение вектора инициализации (синхропосылка)
	copy(iv_buf[:], iv[:])

	// итерация по блокам входящей строки (блоки по 16 байт или 128 бит)
	// i увеличивается на блок 16 байт
	for i := 0; i < len(in); i += 16 {
		// копирование блока 16 байт исходной строки в буфер
		copy(in_buf[:], in[i:i+16])
		// применение функции зашифрования с простой заменой (ecb) c записью в буфер выходных значений
		out_buf = aesDecEcb(in_buf, roundKey, nk, nr)
		// сложение блока исходного текста со значением в буфере вектора инициализации (синхропосылки)
		// для первого раунда это значение вектора инициализации переданного аргументом функции
		// для последующих раундов это предыдущий блок шифртекста
		xorSlice(iv_buf, out_buf)
		// запись получившихся значений из буфера в выходную строку
		out = append(out, out_buf...)
		// копирование текущего блока шифртекста в буфер вектора инициализации (с заменой)
		copy(iv_buf[:], in_buf[:])
	}

	// возврат итоговой строки
	return out
}

// Процедура зашифрования в режиме ecb (режим простой замены)
func aesEncEcb(in []byte, roundKey []byte, nk int, nr int) []byte {
	// создание выходной строки и буфера для блока зашифрованного текста
	out := make([]byte, 0)
	out_buf := make([]byte, 16)

	// итерация по блокам входящей строки (блоки по 16 байт или 128 бит)
	// i увеличивается на блок 16 байт
	for i := 0; i < len(in); i += 16 {
		// процедура зашифрования блока текста
		encryptBlock(in[i:i+16], roundKey, nr, out_buf)
		// запись зашифрованного блока в выходную строку
		out = append(out, out_buf...)
	}

	// возрат выходной строки (результат зашифрования / шифртекст)
	return out
}

// Процедура расшифрования в режиме ecb (режим простой замены)
func aesDecEcb(in []byte, roundKey []byte, nk int, nr int) []byte {
	// создание выходной строки и буфера для блока расшифрованного текста
	out := make([]byte, 0)
	out_buf := make([]byte, 16)

	// итерация по блокам входящей строки (блоки по 16 байт или 128 бит)
	// i увеличивается на блок 16 байт
	for i := 0; i < len(in); i += 16 {
		// процедура зашифрования блока шифртекста
		decryptBlock(in[i:i+16], roundKey, nr, out_buf)
		// запись расшифрованного блока в выходную строку
		out = append(out, out_buf...)
	}

	// возрат выходной строки (результат расшифрования / текст)
	return out
}

/* Процедура дополнения текста до блока нужного размера */
func PKCS7Padding(data *[]byte, blockSize int) {
	// расчет недостающего количество байт в блоке
	padNum := blockSize - (len(*data) % blockSize)

	// если количество 0, устанавливается значение размера блока
	if padNum == 0 {
		padNum = blockSize
	}

	// добавление необходимого количество байт со значением соответствующим этому количеству
	for i := 0; i < padNum; i++ {
		*data = append(*data, byte(padNum))
	}
}

/* Процедура удаления дополнений текста */
func PKCS7UnPadding(data *[]byte) {
	// получение значения добавленных данных (выбор последнего элемента, его значение соответствует количеству)
	padNum := (*data)[len(*data)-1]
	// удаление добавленных блоков
	*data = (*data)[0 : len(*data)-int(padNum)]
}

/* Процедура управления зашифрованием / расшифрованием */
func encOrDecProcedure(key string, text []byte, enc bool, dec bool, mode string) []byte {
	// переменная для хранения результата
	var result []byte
	// объявление переменных, зависимых от размера ключа
	// nk - количество 32 битных блоков ключа
	// nr - количество раундов зашифрования / расшифрования
	var nk, nr int

	// создание буфера для хранения
	roundKey := make([]byte, 240)

	// установка переменных в зависимости от длины ключа
	switch len(key) * 8 {
	case 128:
		nk = AES_128_NK
		nr = AES_128_NR
	case 192:
		nk = AES_192_NK
		nr = AES_192_NR
	case 256:
		nk = AES_256_NK
		nr = AES_256_NR
	}

	// Процедура выработки раундовых ключей
	keyExpansion([]byte(key), roundKey, nk, nr)

	// Перевод текста / шифртекста из строки в байты
	textInByte := []byte(text)

	// Проверка режима работы
	if enc {
		// Режим зашифрования
		// Дополнение текста до кратности блоку 16 байт
		PKCS7Padding(&textInByte, 16)
		// Проверка режима зашифрования
		if mode == "ecb" {
			// Режим ecb (режим простая замена)
			// Процедура зашифрования в режиме ecb (режим простой замены)
			result = aesEncEcb(textInByte, roundKey, nk, nr)
		} else if mode == "cbc" {
			// Режим cbc (Режим сцепления блоков шифротекста)
			// Созание буфера для вектро инициализации
			iv := make([]byte, 16)
			// Заполнение вектора инициализации случайными значениями
			_, err := rand.Read(iv)
			if err != nil {
				fmt.Printf("Ошибка при создании input vector для cbc: %s\n", err)
				os.Exit(1)
			}
			// Процедура зашифрования в режиме cbc (Режим сцепления блоков шифротекста)
			result = aesEncCbc(textInByte, roundKey, nk, nr, iv)
			// Добавление вектора инициализации в начало шифртекста
			result = append(iv, result...)
		}
	} else if dec {
		// Режим расшифрования
		// Проверка режима расшифрования
		if mode == "ecb" {
			// Режим ecb (режим простая замена)
			// Процедура расшифрования в режиме ecb (режим простой замены)
			result = aesDecEcb(textInByte, roundKey, nk, nr)
		} else if mode == "cbc" {
			// Режим cbc (Режим сцепления блоков шифротекста)
			// Чтение вектора инициализации из начала шифртекста (первые 16 байт)
			iv := textInByte[0:16]
			// Процедура расшифрования в режиме cbc (Режим сцепления блоков шифротекста)
			result = aesDecCbc(textInByte[16:], roundKey, nk, nr, iv)
		}
		// Удаление дополнения текста
		PKCS7UnPadding(&result)
	}

	// Возврат результата
	return result
}

// Основаня фукнция программы (входная точка в программу)
func main() {
	// установка перчня флагов (аргументов) принимаемых программой с их описанием
	fPath := flag.String("f", "", "Путь к файлу для зашифрования или расшифрования")
	outputPath := flag.String("o", "", "Путь к файлу с результатами зашифрования или расшифрования файла переданного в -f")
	key := flag.String("k", "", "Ключ шифрования")
	enc := flag.Bool("enc", false, "Запуск в режиме зашифрования")
	dec := flag.Bool("dec", false, "Запуск в режиме расшифрования")
	mode := flag.String("mode", "cbc", "Режим шифрования. Поддерживается два режима: ecb или cbc. По умолчанию cbc.")

	// считывание флагов
	flag.Parse()

	// проверка переданных флагов
	// если не укзаан путь к файлу или ключ - вернуть ошибку
	if *fPath == "" || *key == "" {
		fmt.Println("Необходимо указать путь к файлу и ключ шифрования")
		os.Exit(1)
	}

	// если длина ключа не 128, 192, 256 бит - вернуть ошибку
	lenKeyBytes := len(*key) * 8
	if lenKeyBytes != 128 && lenKeyBytes != 192 && lenKeyBytes != 256 {
		fmt.Println("Длина ключа должна быть 128, 192 или 256 бит")
		os.Exit(1)
	}

	// если не укзаан режим работы программы - вернуть ошибку
	if !*enc && !*dec {
		fmt.Println("Необходимо выбрать режим работы программы (установите enc или dec)")
		os.Exit(1)
	}

	// если указаны оба режима одновременно - вернуть ошибку
	if *enc && *dec {
		fmt.Println("Необходимо выбрать один режим работы программы (установите только enc или dec)")
		os.Exit(1)
	}

	// если укзаан неизвестный режим шифрования - вернуть ошибку
	if *mode != "ecb" && *mode != "cbc" {
		fmt.Println("Необходимо выбрать режим шифрования ecb или cbc")
		os.Exit(1)
	}

	// чтение текста / шифртекста из файла
	text, err := os.ReadFile(*fPath)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Вызов основной процедуры
	result := encOrDecProcedure(*key, text, *enc, *dec, *mode)

	// запись текста / шифртекста в файла
	err = os.WriteFile(*outputPath, result, 0600)
	if err != nil {
		fmt.Printf("Ошибка при записи файла: %s\n", err)
		os.Exit(1)
	}
}
