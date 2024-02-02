#include <iostream>
#include <string>
#include <cctype>  
#include <random>
#include <regex> //check email address
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <iomanip>//important for manipulation in Hex, setw, setfill, hash[i]
#include <fstream> //for file handling
#include <vector>
#include <algorithm> // Include for std::find

struct User{
    std::string email;
    std::string password;
    std::string saltWithEmail;
    std::string saltWithPassword;
    std::string hashedEmailMD5;
    std::string hashedPasswordMD5;
    std::string hashedEmailSHA256;
    std::string hashedPasswordSHA256;

    bool validPassword() const{
        return password.length() >= 9 &&
               std::any_of(password.begin(), password.end(), ::isupper) &&
               std::any_of(password.begin(), password.end(), ::islower) &&
               std::any_of(password.begin(), password.end(), ::isdigit) &&
               std::any_of(password.begin(), password.end(), ::ispunct);
    }

    void generateSalt(std::string& salt, int randomStringLength){
        salt.clear();
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> distribution(65, 90);

        for(int i = 0; i < randomStringLength; ++i){
            char randomChar = static_cast<char>(distribution(gen));
            salt += randomChar;
        }
    }

    void hashMD5(const std::string& input, std::string& hashed){
        MD5_CTX ctx;
        MD5_Init(&ctx);
        MD5_Update(&ctx, input.c_str(), input.length());

        unsigned char hash[MD5_DIGEST_LENGTH];
        MD5_Final(hash, &ctx);

        hashed.clear();
        for(int i = 0; i < MD5_DIGEST_LENGTH; ++i){
            hashed += (char)(hash[i]);
        }
    }

    void hashSHA256(const std::string& input, std::string& hashed){
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, input.c_str(), input.length());

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_Final(hash, &ctx);

        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i){
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }

        hashed = ss.str();
    }

    void generateHashes(){
        hashMD5(email + saltWithEmail, hashedEmailMD5);
        hashMD5(password + saltWithPassword, hashedPasswordMD5);
        hashSHA256(email + saltWithEmail, hashedEmailSHA256);
        hashSHA256(password + saltWithPassword, hashedPasswordSHA256);
    }

    void writeInFile(std::ofstream& outFile)const{
        outFile << "Email MD5: " << hashedEmailMD5 << std::endl;
        outFile << "Password MD5: " << hashedPasswordMD5 << std::endl;
        outFile << "Email SHA256: " << hashedEmailSHA256 << std::endl;
        outFile << "Password SHA256: " << hashedPasswordSHA256 << std::endl;
        outFile << "---------------------" << std::endl;
    }
};

//struct for common passwords
struct Common{
    std::string common;
    std::string commonMD5;
    std::string commonSHA256;
    std::string addedToPass;  // Added member to store modified password
    std::string addedToPassMD5;
    std::string addedToPassSHA256;

    // MD5 hashing function
    std::string md5(const std::string &input){
        MD5_CTX ctx;
        MD5_Init(&ctx);
        MD5_Update(&ctx, input.c_str(), input.length());

        unsigned char hash[MD5_DIGEST_LENGTH];
        MD5_Final(hash, &ctx);

        std::string result;
        for(int i = 0; i < MD5_DIGEST_LENGTH; ++i){
            result += (char)(hash[i]);
        }
        return result;
    }
    // SHA256 hashing function
    std::string sha256(const std::string &input){
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, input.c_str(), input.length());

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_Final(hash, &ctx);

        std::stringstream ss;
        for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i){
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }

        return ss.str();
    }
    
    //this function can have any string (2024 is just as an example)
    void addStringToPassword(){
        addedToPass = common + "2024";
        hashCommon();
    }

    // Hash common password in MD5 and SHA256
    void hashCommon(){
        commonMD5 = md5(common);
        commonSHA256 = sha256(common);
        addedToPassMD5 = md5(addedToPass);
        addedToPassSHA256 = sha256(addedToPass);
    }
    // Write and store hashed data in text file
    void writeInFile(std::ofstream &outFile) const{
        outFile << "Common password: " << common << std::endl;
        outFile << "Common password in MD5: " << commonMD5 << std::endl;
        outFile << "Common password in SHA256: " << commonSHA256 << std::endl;
        outFile << "Modified password: " << addedToPass << std::endl;
        outFile << "Modified password in MD5: " << addedToPassMD5 << std::endl;
        outFile << "Modified password in SHA256: " << addedToPassSHA256 << std::endl;
        outFile << "---------------------" << std::endl;
    }

    //this should compare later on hashed passwords
    bool checkCrack(const std::string& hashedPassword)const{
        return(hashedPassword == commonMD5)||(hashedPassword == commonSHA256)||
            (hashedPassword == addedToPassMD5)||(hashedPassword == addedToPassSHA256);
    }
};

int main(){

    //here comes 100 common passwords part from
    //https://mailsafi.com/blog/top-200-most-common-passwords/

    std::vector<std::string> commonPass{"123456", "123456789","picture1", "password",
    "12345678", "11111", "123123", "12345", "1234567890", "senha", "1234567",
    "qwerty", "abc123", "Million2", "000000", "1234", "iloveyou", "aaron431",
    "password1", "qqww1122", "123", "omgpop", "123321", "654321", "qwertyuiop", 
    "qwer123456", "123456a", "a123456", "666666","asdfghjkl","ashley","987654321",
    "unknown","zxcvbnm","112233","chatbooks","20100728","123123123","princess",
    "jacket025", "evite","123abc","123qwe","sunshine","121212","dragon","1q2w3e4r",
    "5201314","159753","123456789","pokemon","qwerty123","Bangbang123","jobandtalent",
    "monkey","1qaz2wsx","abcd1234","default","aaaaaa","soccer","123654","ohmnamah23",
    "12345678910","zing","shadow","102030","11111111","asdfgh","147258369","qazwsx",
    "qwe123","michael","football","baseball","1q2w3e4r5t","party","daniel","asdasd",
    "222222","myspace1","asd123","555555","	a123456789","888888","7777777","fuckyou",
    "1234qwer", "superman","147258","999999","159357","love123","tigger","purple",
    "samantha","charlie","babygirl","88888888","jordan23","789456123"};
    
    //just to check if it is 100 passwords :)
    //std::size_t vectorSize = commonPass.size();
    //std::cout<<"size:"<<vectorSize<<std::endl;

    std::vector<Common> commonPasswords;
    for(const auto &password : commonPass){
        Common commonPassword;
        commonPassword.common = password;
        commonPassword.hashCommon();
        commonPasswords.push_back(commonPassword);
    }

    // Store common passwords and their hashes in a text file
    std::ofstream commonFile("common.txt");
    if(!commonFile.is_open()) {
        std::cerr << "Error with file!" << std::endl;
        return 1;
    }
    for(const auto &commonPassword : commonPasswords){
        commonPassword.writeInFile(commonFile);
    }
    commonFile.close();

    std::cout << "Common Data stored successfully." << std::endl;

//****************************************************************************************
    std::vector<User> users; //users storing in vector
    std::string input;
    User newUser;

    //email part
    while (true) {
        std::cout << "Enter an email address: ";
        std::getline(std::cin, newUser.email);

        // Check if the email address is valid
        std::regex emailPattern(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
        if(!std::regex_match(newUser.email, emailPattern)){
            std::cout << "Invalid email address.\n";
            continue;
        }

        // Check if the email address already exists aka test login
        if(std::find_if(users.begin(), users.end(),
            [&newUser](const User& u) { return u.email == newUser.email; }) != users.end()) {
            std::cout << "Email address already exists. Please enter a different one.\n";
            continue;
        }

        std::cout << "Valid email address.\n";

        // Password part
        do{
            std::cout << "Enter password: ";
            std::getline(std::cin, newUser.password);

            if(newUser.validPassword()){
                std::cout << "Password approved! " << std::endl;
                break;
            }
            else{
                std::cout << "Invalid password, try again: " << std::endl;
            }

        }while(true);

        newUser.generateSalt(newUser.saltWithEmail, 15);
        newUser.generateSalt(newUser.saltWithPassword, 15);
        newUser.generateHashes();
        users.push_back(newUser);

        // Ask the user if they want to continue
        std::cout << "Do you want to enter another user? (yes/no): ";
        std::getline(std::cin, input);
        for(char& c : input){
            c = std::tolower(c);
        }

        if(input != "yes" && input != "y"){
            break;
        }
    }

    // Store user data in hashed.txt
    std::ofstream outFile("hashed.txt");
    if(!outFile.is_open()){
        std::cerr << "Error with file!" << std::endl;
        return 1;
    }

    for(const auto& user : users){
        user.writeInFile(outFile);
    }

    outFile.close();

    std::cout << "Hashed data stored successfully." << std::endl;

//**********************************************************************************
//password cracker part
//user can write hashed wersion and it will compare it with common.txt
    
    while(true){
        std::cout << "Wanna have some (i)llegal fun? yes/no " << std::endl;
        std::getline(std::cin, input);

        for(char& c : input){
            c = std::tolower(c);
        }

        if(input != "yes" && input != "y"){
            break;
        }

        std::string crackinCracker;
        std::cout << "Write hashed password you wish to crack: " << std::endl;
        std::getline(std::cin, crackinCracker);

        // Check if the provided hashed password matches any in the common passwords
        bool cracked = false;
        for(const auto& commonPassword : commonPasswords){
            if(commonPassword.checkCrack(crackinCracker)){
                std::cout << "Password cracked! Original password: " << commonPassword.common << std::endl;
                cracked = true;
                break;
            }
        }

        if(!cracked){
            std::cout << "Password not found in common passwords." << std::endl;
        }

        std::cout <<"Wanna continue? (yes/no): ";
        std::getline(std::cin, input);

        for(char& c : input){
            c = std::tolower(c);
        }

        if(input != "yes" && input != "y"){
            break;
        }
    }

    return 0;

}

