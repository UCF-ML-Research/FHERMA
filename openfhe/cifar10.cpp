#include "cifar10.h"

#define STB_IMAGE_IMPLEMENTATION

#include "stb_image.h"

CIFAR10CKKS::CIFAR10CKKS(
        string ccLocation, string pubKeyLocation, string secKeyLocation, string multKeyLocation, string rotKeyLocation,
        string inputLocation, string outputLocation, string mode
) : m_PubKeyLocation(pubKeyLocation), m_SecKeyLocation(secKeyLocation),
    m_MultKeyLocation(multKeyLocation), m_RotKeyLocation(rotKeyLocation),
    m_CCLocation(ccLocation), m_InputLocation(inputLocation), m_OutputLocation(outputLocation) {

    if (mode == "gen")
        genCC();
    else
        initCC(1);
};


CIFAR10CKKS::CIFAR10CKKS(
        string ccLocation, string pubKeyLocation, string multKeyLocation, string rotKeyLocation,
        string inputLocation, string outputLocation
) :
        m_PubKeyLocation(pubKeyLocation), m_MultKeyLocation(multKeyLocation), m_RotKeyLocation(rotKeyLocation),
        m_CCLocation(ccLocation), m_InputLocation(inputLocation), m_OutputLocation(outputLocation) {

    initCC();

};


void CIFAR10CKKS::initCC(int test) {
    if (!Serial::DeserializeFromFile(m_CCLocation, m_cc, SerType::BINARY)) {
        cerr << "Could not deserialize cryptocontext file" << endl;
        exit(1);
    }

    if (!Serial::DeserializeFromFile(m_PubKeyLocation, m_PublicKey, SerType::BINARY)) {
        cerr << "Could not deserialize public key file" << endl;
        exit(1);
    }

    if (test==1){
        if (!Serial::DeserializeFromFile(m_SecKeyLocation, m_SecretKey, SerType::BINARY)) {
            cerr << "Could not deserialize secret key file" << endl;
            exit(1);
        }
    }

    ifstream multKeyIStream(m_MultKeyLocation, ios::in | ios::binary);
    if (!multKeyIStream.is_open()) {
        exit(1);
    }
    if (!m_cc->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY)) {
        cerr << "Could not deserialize rot key file" << endl;
        exit(1);
    }

    ifstream rotKeyIStream(m_RotKeyLocation, ios::in | ios::binary);
    if (!rotKeyIStream.is_open()) {
        exit(1);
    }

    if (!m_cc->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY)) {
        cerr << "Could not deserialize eval rot key file" << endl;
        exit(1);
    }

    if (!Serial::DeserializeFromFile(m_InputLocation, m_InputC, SerType::BINARY)) {
        cerr << "Could not deserialize Input ciphertext" << endl;
        exit(1);
    }
    if (test == 1) {
        cout << "Step 1" << endl;
        vector<double> res_clean = decrypt_to_vector(m_InputC, 4096);
        for (int i = 0; i < 10; i++)
            cout << res_clean[i] << " ";
        cout << endl;
    }

}

void CIFAR10CKKS::genCC() {
    // Set up the parameters
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetRingDim(num_slots*2);
    parameters.SetScalingModSize(59);
    parameters.SetFirstModSize(60);
    parameters.SetBatchSize(num_slots);

    // Generate the CryptoContext
    m_cc = GenCryptoContext(parameters);

    m_cc->Enable(PKE);
    m_cc->Enable(KEYSWITCH);
    m_cc->Enable(LEVELEDSHE);
    m_cc->Enable(ADVANCEDSHE);
    m_cc->Enable(FHE);

    KeyPair<DCRTPoly> key_pair = m_cc->KeyGen();
    m_SecretKey = key_pair.secretKey;
    m_PublicKey = key_pair.publicKey;

    vector<int32_t> rotations = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 32, 33, 34, 64, 65, 66, 128, 256, 512, 1024, 2048, 4096, 8192};
    m_cc->EvalRotateKeyGen(m_SecretKey, rotations);
    m_cc->EvalMultKeyGen(m_SecretKey);

    cout << "Now serializing keys ..." << endl;

    ofstream multKeyFile(m_MultKeyLocation, ios::out | ios::binary);
    if (multKeyFile.is_open()) {
        if (!m_cc->SerializeEvalMultKey(multKeyFile, SerType::BINARY)) {
            cerr << "Error writing eval mult keys" << std::endl;
            exit(1);
        }
        cout << "Relinearization Keys have been serialized" << std::endl;
        multKeyFile.close();
    }
    else {
        cerr << "Error serializing EvalMult keys in " << m_MultKeyLocation << endl;
        exit(1);
    }

    if (!Serial::SerializeToFile(m_CCLocation, m_cc, SerType::BINARY)) {
        cerr << "Error writing serialization of the crypto context to crypto-context.txt" << endl;
    } else {
        cout << "Crypto Context have been serialized" << std::endl;
    }

    if (!Serial::SerializeToFile(m_PubKeyLocation, m_PublicKey, SerType::BINARY)) {
        cerr << "Error writing serialization of public key to " << m_PubKeyLocation << endl;
    } else {
        cout << "Public Key has been serialized" << std::endl;
    }

    if (!Serial::SerializeToFile("../keys/secret-key.txt", m_SecretKey, SerType::BINARY)) {
        cerr << "Error writing serialization of public key to secret-key.txt" << endl;
    } else {
        cout << "Secret Key has been serialized" << std::endl;
    }

    std::ofstream rotKeyOStream(m_RotKeyLocation, std::ios::out | std::ios::binary);
    if (rotKeyOStream.is_open()) {
        if (!m_cc->SerializeEvalAutomorphismKey(rotKeyOStream, SerType::BINARY)) {
            cerr << "Error writing eval automorphism keys" << std::endl;
            exit(1);
        }
        cout << "Rotation Keys have been serialized" << std::endl;
        rotKeyOStream.close();
    } else {
        cerr << "Error serializing EvalAutomorphism keys in " << m_RotKeyLocation << endl;
        exit(1);
    }

    string input_filename = "../inputs/test.png";
    vector<double> input_image = read_image(input_filename.c_str());

    m_InputC = encrypt(input_image, 0);

    if (!Serial::SerializeToFile(m_InputLocation, m_InputC, SerType::BINARY)) {
        cerr << "Error writing ciphertext 1" << endl;
    } else {
        cout << "Input ciphertext has been serialized" << endl;
    }

}

vector<double> CIFAR10CKKS::read_image(const char *filename) {
    int width = 32;
    int height = 32;
    int channels = 3;
    unsigned char *image_data = stbi_load(filename, &width, &height, &channels, 0);

    if (!image_data) {
        cerr << "Could not load the image in " << filename << endl;
        return {};
    }

    vector<double> imageVector;
    imageVector.reserve(width * height * channels);

    for (int i = 0; i < width * height; ++i) {
        //Channel R
        imageVector.push_back(static_cast<double>(image_data[3 * i]));
    }
    for (int i = 0; i < width * height; ++i) {
        //Channel G
        imageVector.push_back(static_cast<double>(image_data[1 + 3 * i]));
    }
    for (int i = 0; i < width * height; ++i) {
        //Channel B
        imageVector.push_back(static_cast<double>(image_data[2 + 3 * i]));
    }

    stbi_image_free(image_data);

    ofstream outFile("input.txt");
    if (outFile.is_open()) {
        for (auto val: imageVector) {
            outFile << val << " ";
        }
        outFile.close();
    } else {
        std::cerr << "Unable to open file for writing." << std::endl;
    }

    return imageVector;
}


Plaintext CIFAR10CKKS::encode(const vector<double> &vec, int level) {
    size_t encoded_size = vec.size();

    Plaintext p = m_cc->MakeCKKSPackedPlaintext(vec, 1, level);
    p->SetLength(encoded_size);

    return p;
}


Ciphertext<DCRTPoly> CIFAR10CKKS::encrypt(const vector<double> &vec, int level) {
    Plaintext p = encode(vec, level);
    return m_cc->Encrypt(p, m_PublicKey);
}


vector<double> CIFAR10CKKS::decrypt_to_vector(const Ciphertext<DCRTPoly> &c, int slots) {
    if (slots == 0) {
        slots = num_slots;
    }

    Plaintext p;
    m_cc->Decrypt(m_SecretKey, c, &p);
    p->SetLength(slots);
    vector<double> vec = p->GetRealPackedValue();
    return vec;
}

void CIFAR10CKKS::store_res(Ciphertext<DCRTPoly> res, string filename){
    vector<double> res_clean = decrypt_to_vector(res, 16384);
    std::ofstream file(filename);
    if (!file) {
        std::cerr << "Error opening file for writing: " << filename << std::endl;
        return;
    }
    for (const double& val : res_clean) {
        file << val << '\n';
    }
    file.close();
}

Ciphertext<DCRTPoly> CIFAR10CKKS::model_conv3x16_square_fc(Ciphertext<DCRTPoly> &in) {
    Ciphertext<DCRTPoly> res1 = conv3x16(in, 1);
    res1 = relu_square(res1);
    Ciphertext<DCRTPoly> res = fc16384x10(res1, 1);

    return res;
}

Ciphertext<DCRTPoly> CIFAR10CKKS::model_conv3x8_square_fc(Ciphertext<DCRTPoly> &in) {
    Ciphertext<DCRTPoly> res1 = conv3x8(in, 1);
    res1 = relu_square(res1);
    Ciphertext<DCRTPoly> res = fc8192x10(res1, 1);

    return res;
}

void CIFAR10CKKS::eval(){
    Ciphertext<DCRTPoly> in = m_cc->EvalMult(m_InputC, 1/255.0);
    m_OutputC = model_conv3x16_square_fc(in);
    store_res(m_OutputC, "../temp/fc_res.txt");
}


void CIFAR10CKKS::serializeOutput() {
    if (!Serial::SerializeToFile(m_OutputLocation, m_OutputC, SerType::BINARY)) {
        cerr << " Error writing ciphertext 1" << endl;
    }
}

std::vector<std::vector<std::vector<double>>> readBinaryTensor(const std::string& filename, int dim1, int dim2, int dim3) {
    const int total_elements = dim1 * dim2 * dim3;

    std::vector<float> data(total_elements);

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file!");
    }
    file.read(reinterpret_cast<char*>(data.data()), total_elements * sizeof(float));
    file.close();

    if (!file) {
        throw std::runtime_error("Error reading file!");
    }

    std::vector<std::vector<std::vector<double>>> tensor(dim1, std::vector<std::vector<double>>(dim2, std::vector<double>(dim3)));

    for (int i = 0; i < dim1; ++i) {
        for (int j = 0; j < dim2; ++j) {
            for (int k = 0; k < dim3; ++k) {
                tensor[i][j][k] = static_cast<double>(data[i * dim2 * dim3 + j * dim3 + k]);
            }
        }
    }

    return tensor;
}

Ciphertext<DCRTPoly> CIFAR10CKKS::conv3x16(const Ciphertext<DCRTPoly> &in, double scale) {
    vector<Ciphertext<DCRTPoly>> c_rotations;

    c_rotations.push_back(in);
    c_rotations.push_back(m_cc->EvalRotate(in, 1));
    c_rotations.push_back(m_cc->EvalRotate(in, 2));
    c_rotations.push_back(m_cc->EvalRotate(in, 32));
    c_rotations.push_back(m_cc->EvalRotate(in, 33));
    c_rotations.push_back(m_cc->EvalRotate(in, 34));
    c_rotations.push_back(m_cc->EvalRotate(in, 64));
    c_rotations.push_back(m_cc->EvalRotate(in, 65));
    c_rotations.push_back(m_cc->EvalRotate(in, 66));

    Ciphertext<DCRTPoly> finalsum;

    for (int c = 0; c < 16; c++) {
        vector<Ciphertext<DCRTPoly>> k_rows;
        for (int k = 0; k < 9; k++) {
            vector<double> weights = read_values_from_file(m_WeightsDir + "/conv1-ch" + to_string(c) + "-k" + to_string(k) + ".bin", scale);
            Plaintext encoded = encode(weights, in->GetLevel());
            k_rows.push_back(m_cc->EvalMult(c_rotations[k], encoded));
        }

        Ciphertext<DCRTPoly> sum = m_cc->EvalAddMany(k_rows);
        Ciphertext<DCRTPoly> res = sum->Clone();
        Ciphertext<DCRTPoly> sum_shift = m_cc->EvalRotate(sum, 1024);

        res = m_cc->EvalAdd(res, sum_shift);
        res = m_cc->EvalAdd(res, m_cc->EvalRotate(sum_shift, 1024));

        Plaintext bias=  encode(read_values_from_file(m_WeightsDir + "/conv1-ch" + to_string(c) + "-bias.bin", scale), res->GetLevel());
        res = m_cc->EvalAdd(res, bias);

        Plaintext mask = encode(read_values_from_file(m_WeightsDir + "/conv1-mask.bin", scale), res->GetLevel());
        res = m_cc->EvalMult(res, mask);

        if (c == 0) {
            finalsum = res->Clone();
            finalsum = m_cc->EvalRotate(finalsum, 1024);
        } else {
            finalsum = m_cc->EvalAdd(finalsum, res);
            finalsum = m_cc->EvalRotate(finalsum, 1024);
        }
    }
    return finalsum;
}

Ciphertext<DCRTPoly> CIFAR10CKKS::conv3x8(const Ciphertext<DCRTPoly> &in, double scale) {
    vector<vector<vector<double>>> weights_all = readBinaryTensor(m_WeightsDir + "/conv1-weights.bin", 8, 9, 3072);


    vector<Ciphertext<DCRTPoly>> c_rotations;

    c_rotations.push_back(in);
    c_rotations.push_back(m_cc->EvalRotate(in, 1));
    c_rotations.push_back(m_cc->EvalRotate(in, 2));
    c_rotations.push_back(m_cc->EvalRotate(in, 32));
    c_rotations.push_back(m_cc->EvalRotate(in, 33));
    c_rotations.push_back(m_cc->EvalRotate(in, 34));
    c_rotations.push_back(m_cc->EvalRotate(in, 64));
    c_rotations.push_back(m_cc->EvalRotate(in, 65));
    c_rotations.push_back(m_cc->EvalRotate(in, 66));

    Ciphertext<DCRTPoly> finalsum;

    for (int c = 0; c < 8; c++) {
        vector<Ciphertext<DCRTPoly>> k_rows;
        for (int k = 0; k < 9; k++) {
//            vector<double> weights = read_values_from_file(m_WeightsDir + "/conv1-ch" + to_string(c) + "-k" + to_string(k) + ".bin", scale);
            vector<double> weights = weights_all[c][k];
            Plaintext encoded = encode(weights, in->GetLevel());
            k_rows.push_back(m_cc->EvalMult(c_rotations[k], encoded));
        }

        Ciphertext<DCRTPoly> sum = m_cc->EvalAddMany(k_rows);
        Ciphertext<DCRTPoly> res = sum->Clone();
        Ciphertext<DCRTPoly> sum_shift = m_cc->EvalRotate(sum, 1024);

        res = m_cc->EvalAdd(res, sum_shift);
        res = m_cc->EvalAdd(res, m_cc->EvalRotate(sum_shift, 1024));

        Plaintext bias = encode(read_values_from_file(m_WeightsDir + "/conv1-ch" + to_string(c) + "-bias.bin", scale), res->GetLevel());
        res = m_cc->EvalAdd(res, bias);

        Plaintext mask = encode(read_values_from_file(m_WeightsDir + "/conv1-mask.bin", scale), res->GetLevel());
        res = m_cc->EvalMult(res, mask);

        if (c == 0) {
            finalsum = res->Clone();
            finalsum = m_cc->EvalRotate(finalsum, 1024);
        } else {
            finalsum = m_cc->EvalAdd(finalsum, res);
            finalsum = m_cc->EvalRotate(finalsum, 1024);
        }
    }

    return finalsum;
}

Ciphertext<DCRTPoly> CIFAR10CKKS::fc16384x10(const Ciphertext<DCRTPoly> &in, double scale) {
    Ciphertext<DCRTPoly> finalsum;
    vector<int> rolls = {8192, 4096, 2048, 1024, 512, 256, 128, 64, 32, 16};

    for (int i = 0; i < 16; i++) {
        vector<double> weights = read_values_from_file(m_WeightsDir + "/fc-c" + to_string(i) + ".bin", scale);
        Plaintext encoded = encode(weights, in->GetLevel());
        if (i == 0)
            finalsum = m_cc->EvalMult(in, encoded);
        else{
            Ciphertext<DCRTPoly> current = m_cc->EvalMult(m_cc->EvalRotate(in, i), encoded);
            finalsum = m_cc->EvalAdd(finalsum, current);
        }
    }

    for (int r: rolls)
        finalsum = m_cc->EvalAdd(m_cc->EvalRotate(finalsum, r), finalsum);

    Plaintext bias = encode(read_values_from_file(m_WeightsDir + "/fc-bias.bin", scale), finalsum->GetLevel());
    finalsum = m_cc->EvalAdd(finalsum, bias);

    return finalsum;
}

Ciphertext<DCRTPoly> CIFAR10CKKS::fc8192x10(const Ciphertext<DCRTPoly> &in, double scale) {
    Ciphertext<DCRTPoly> finalsum;
    vector<int> rolls = {4096, 2048, 1024, 512, 256, 128, 64, 32, 16};

    for (int i = 0; i < 16; i++) {
        vector<double> weights = read_values_from_file(m_WeightsDir + "/fc-c" + to_string(i) + ".bin", scale);
        Plaintext encoded = encode(weights, in->GetLevel());
        if (i == 0)
            finalsum = m_cc->EvalMult(in, encoded);
        else{
            Ciphertext<DCRTPoly> current = m_cc->EvalMult(m_cc->EvalRotate(in, i), encoded);
            finalsum = m_cc->EvalAdd(finalsum, current);
        }
    }

    for (int r: rolls)
        finalsum = m_cc->EvalAdd(m_cc->EvalRotate(finalsum, r), finalsum);

    Plaintext bias = encode(read_values_from_file(m_WeightsDir + "/fc-bias.bin", scale), finalsum->GetLevel());
    finalsum = m_cc->EvalAdd(finalsum, bias);

    return finalsum;
}

Ciphertext<DCRTPoly> CIFAR10CKKS::relu_square(const Ciphertext<DCRTPoly> &in) {
    return m_cc->EvalMult(in, in);
}