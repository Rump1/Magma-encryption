#include <vector>
#include <string>
#include <iostream>
using namespace std;

const int T_Transformation [8][16] = // Матрица для нелинейного биективного преобразования
{
{ 1,  7,  14, 13, 0,  5,  8,  3,  4,  15, 10, 6,  9,  12, 11, 2   },
{ 8,  14, 2,  5,  6,  9,  1,  12, 15, 4,  11, 0,  13, 10, 3,  7   },
{ 5,  13, 15, 6,  9,  2,  12, 10, 11, 7,  8,  1,  4,  3,  14, 0   },
{ 7,  15, 5,  10, 8,  1,  6,  13, 0,  9,  3,  14, 11, 4,  2,  12  },
{ 12, 8,  2,  1,  13, 4,  15, 6,  7,  0,  10, 5,  3,  14, 9,  11  },
{ 11, 3,  5,  8,  2,  15, 10, 13, 14, 1,  7,  4,  12, 9,  6,  0   },
{ 6,  8,  2,  3,  9,  10, 5,  12, 1,  14, 4,  7,  11, 13, 0,  15  },
{ 12, 4,  6,  2,  10, 5,  11, 9,  14, 8,  13, 7,  0,  3,  15, 1   }
};


static unsigned long long Text_To_Number(string input)
{
    unsigned long long result = 0;
    for (int i = 0; i < input.length(); i++)
    {
        result <<= 8;
        if (input[i] < 0)
        {
            result += input[i] + 256 ;
        }
        else
        {
            result += input[i];
        }
    }
    return result;
}

static string Number_To_Text(unsigned long long number)
{
    string result = "";
    for (int i = 0; i < 8; i++)
    {
        result = (char)(number % 256) + result;
        number /= 256;
    }
    return result;
}
unsigned int Shift_11_Bit(unsigned int number)
{
    return number << 11 | number >> 21;
}

vector<unsigned int> get_Round_Keys_For_Magma(string general_Key) // Разбиение генерального ключа на раундовые (256 бит на 32)
{
    vector<unsigned int> round_Keys(0);
    for (int i = 0; i < 8; i++)
    {
        round_Keys.push_back((unsigned long)Text_To_Number(general_Key.substr(i * 4, 4)));
    }
    return round_Keys;
}

unsigned int Permutation(unsigned int number) // T - преобразование
{
    unsigned int result = 0;
    for (int j = 0; j < 8; j++)
    {
        result <<= 4;
        result += (unsigned char)T_Transformation[j][number >> 28];
        number <<= 4;
    }
    return result;
}
string Magma_Encrypt(string input, string general_Key, char method) // Магма шифрование, method = e/d, шифрование или дешифрование
{
    vector<unsigned int> round_Keys = get_Round_Keys_For_Magma(general_Key); // Создание массива раундовых ключей
    unsigned long long integer_input = Text_To_Number(input);
    for (int i = 0; i < 32; i++)
    {
        unsigned int round_Key;
        if (tolower(method) == 'e')
        {
            if (i < 24)
                round_Key = round_Keys[i % 8];
            else
                round_Key = round_Keys[7 - (i % 8)];
        }
        else if (tolower(method) == 'd')
        {
            if (i < 8)
                round_Key = round_Keys[i % 8];
            else
                round_Key = round_Keys[7 - (i % 8)];
        }
        else return "Выбран некорректный method. Попробуйте e/d";

        unsigned int left = integer_input >> 32;
        unsigned int right = (integer_input << 32) >> 32;

        right = right + round_Key;  // Сумма по модулю с раундовым ключом
        
        right = Permutation(right); // Нелинейное биективное преобразование T
        
        right = Shift_11_Bit(right); // Смещение на 11 бит
       
        right = right ^ left; // Xor с левой половиной

        if (i != 31)
        {
            integer_input = (integer_input << 32) + right;
        }
        else
        {
            integer_input = ((unsigned long long)right << 32) + ((integer_input << 32) >> 32);
        }
    }
    return Number_To_Text(integer_input);
}

string Cipher_block_Chaining(string input, string vector, string general_key) // Режим сцепления блоков шифрование
{
    string result = "";
    int iterations_count = ceil(input.length() / 8.);
    for (int i = 0; i < iterations_count; i++)
    {
        string str = input.substr(i * 8, 8);
        str.insert(str.length(), 8 - str.length(), '\0');
        vector = Magma_Encrypt(Number_To_Text(Text_To_Number(str) ^ Text_To_Number(vector)), general_key, 'e');
        result = result + vector;
    }
    return result;
}

string Decipher_block_Chaining(string input, string vector, string general_key) // Режим сцепления блоков расшифрование
{
    string result = "";
    int iterations_count = ceil(input.length() / 8.);
    for (int i = 0; i < iterations_count; i++)
    {
        string str = input.substr(i * 8, 8);
        str.insert(str.length(), 8 - str.length(), '\0');
        result += Number_To_Text(Text_To_Number(Magma_Encrypt(str, general_key, 'd')) ^ Text_To_Number(vector));
        vector = str;
    }
    return result;
}
int main()
{
    setlocale(LC_ALL, "ru");
    string general_Key = "12345678901234567890123456789012";
    string vector = "abcdefgh";
    cout << "Введите текст для шифрования: ";
    string input;
    cin >> input;
    string encrypted = Cipher_block_Chaining(input, vector, general_Key);
    cout << "Зашифрованный текст: " + encrypted << endl;
    cout << "Расшифрованный текст: " + Decipher_block_Chaining(encrypted, vector, general_Key);
}

