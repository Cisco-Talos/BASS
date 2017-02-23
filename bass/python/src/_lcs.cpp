#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cassert>
#include <algorithm>
#include <iostream>
#include <vector>
#include <map>
#include <limits>

extern "C" {
    int hirschberg_lcs(const char* x, size_t len_x, const char* y, size_t len_y, char* result, size_t* len_result);
    int hamming_klcs_c(const char** seqs, size_t* seq_lens, size_t num_seqs, char* result, size_t* len_result);
}

/**
 * Calculate the Needleman-Wunsch score matrix.
 * @see https://en.wikipedia.org/wiki/Hirschberg's_algorithm
 * @param x First input string
 * @param y Second input string
 * @return Last line of the score matrix
 */
static std::vector<unsigned int> needleman_wunsch_score(std::string const& x, std::string const& y)
{
    size_t const len_x = x.size();
    size_t const len_y = y.size();
    unsigned int score[2][len_y + 1];

    memset(score, 0, sizeof(score));
    for (unsigned i = 0; i < len_x; ++i) {
        for (unsigned j = 0; j < len_y; ++j) {
            if (x[i] == y[j]) {
                score[(i + 1) % 2][j + 1] = score[i % 2][j] + 1;
            }
            else {
                score[(i + 1) % 2][j + 1] = std::max(
                        score[(i + 1) % 2][j],
                        score[i % 2][j + 1]);
            }
        }
    }

    return std::vector<unsigned int>(&score[len_x % 2][0], &score[len_x % 2][len_y + 1]);
}

/**
 * An implementation of the Hirschberg algorithm, which calculates the longest
 * common subsequence (LCS) in O(x.size() * y.size()) time and O(min(x.size(),
 * y.size())) space.
 * @see https://en.wikipedia.org/wiki/Hirschberg's_algorithm
 * @param x First input string
 * @param y Second input string
 * @return One LCS from the set of LCS(x, y)
 */
static std::string hirschberg(std::string const& x, std::string const& y)
{
    if (x.size() == 0 || y.size() == 0) {
        return std::string();
    }
    else if (x.size() == 1) {
        if (y.find(x[0]) != std::string::npos) {
            return x;
        }
        else {
            return std::string();
        }
    }
    else if (y.size() == 1) {
        if (x.find(y[0]) != std::string::npos) {
            return y;
        }
        else {
            return std::string();
        }
    }
    else {
        size_t const len_y = y.size();
        size_t const xmid = x.size() / 2;
        std::string const xbegin = x.substr(0, xmid);
        std::string const xend = x.substr(xmid);
        std::string const xendrev(xend.rbegin(), xend.rend());
        std::string const yrev(y.rbegin(), y.rend());

        std::vector<unsigned int> score_l = needleman_wunsch_score(xbegin, y);
        std::vector<unsigned int> score_r = needleman_wunsch_score(xendrev, yrev);
        assert(score_l.size() == len_y + 1);
        assert(score_r.size() == len_y + 1); 

        unsigned int max = score_l[0] + score_r[len_y];
        unsigned ymid = 0;

        for (unsigned i = 1; i <= len_y; ++i) {
            if (score_l[i] + score_r[len_y - i] > max) {
                max = score_l[i] + score_r[len_y - i];
                ymid = i;
            }
        }

        std::string const ybegin = y.substr(0, ymid);
        std::string const yend = y.substr(ymid); 

        std::string const common_l = hirschberg(xbegin, ybegin);
        std::string const common_r = hirschberg(xend, yend);

        return common_l + common_r;
    }
}

/**
 * Calculate the hamming distance between a and b.
 * If a and b have a different length, the length difference is added to the
 * hamming distance.
 * @param a First input string
 * @param b Second input string
 * @return Hamming distance between a and b
 */
static inline size_t hamming_distance(std::string const& a, std::string const& b) 
{
    size_t dist = 0;
    for (size_t i = 0, ie = std::min(a.size(), b.size()); i < ie; ++i) {
        if (a[i] != b[i]) {
            dist += 1;
        }
    }

    return dist + std::abs(static_cast<long>(a.size()) - static_cast<long>(b.size()));
}

/**
 * Remove all characters not present in _alphabet_ from _input_.
 * @param input String to filter
 * @param alphabet String with characters to keep
 * @return The string _input_ without any characters not occurring in _alphabet_.
 */
static inline std::string filter_alphabet(std::string const& input, std::string const& alphabet) 
{
    std::map<char, bool> contained;
    std::string result;
    for (char c : alphabet) {
        contained[c] = true;
    }

    for (char c : input) {
        if (contained[c]) {
            result.push_back(c);
        }
    }

    return result;
}

/**
 * An implementation of the Hamming k-LCS algorithm described in Christian
 * Blichmann's thesis.  This algorithm finds a common subsequence between all
 * input strings. The found sequence is not necessarily the longest one, as not
 * the complete multidimensional matrix between all sequences is calculated.
 * Information is lost because the LCS implementation only returns one instance
 * of an LCS from the set of all LCS, and this k-LCS algorithm compares strings
 * with each other with a less expressive metric (Hamming distance) than the
 * LCS algorithm (e.g., comparing with the Levenshtein distance would be
 * better, but also more expensive in terms of computation).
 * @see Christian Blichmann, Automatisierte Signaturgenerierung fuer Malware-Staemme, page 52.
 *      https://static.googleusercontent.com/media/www.zynamics.com/en//downloads/blichmann-christian--diplomarbeit--final.pdf
 * @param seqs Vector of input strings.
 * @return A long common subsequence of all input strings
 */
static std::string hamming_klcs(std::vector< std::string >& seqs)
{
    while (seqs.size() > 2) {
        std::vector< unsigned > kill;
        size_t hmin = std::numeric_limits<size_t>::max();
        ssize_t min_i = 0, min_j = 0;
        
        for (ssize_t i = 0, ie = seqs.size(); i < ie; ++i) {
            for (ssize_t j = 0; j < i; ++j) {
                size_t hcur = hamming_distance(seqs[i], seqs[j]);
                if (hcur == 0) {
                    kill.push_back(i);
                }
                else if (hcur < hmin) {
                    hmin = hcur;
                    min_i = i;
                    min_j = j;
                }
            }
        }

        if (kill.size() == seqs.size() - 1) {
            return seqs[0];
        }
        std::string minlcs = hirschberg(seqs[min_i], seqs[min_j]);
        for (ssize_t k = seqs.size() - 1; k >= 0; --k) {
            if (k == min_i || k == min_j || std::find(kill.begin(), kill.end(), k) != kill.end()) {
                seqs.erase(seqs.begin() + k);
            }
            else {
                seqs[k] = filter_alphabet(seqs[k], minlcs);
            }
        }
        seqs.push_back(minlcs);
    }

    if (seqs.size() > 1) {
        return hirschberg(seqs[0], seqs[1]);
    }
    else {
        return seqs[0];
    }
}

/**
 * C export of the hirschberg LCS function above.
 */
int hirschberg_lcs(const char* buf_x, size_t len_x, const char* buf_y, size_t len_y, char* result, size_t* len_result)
{
    if (!len_result) {
        return -EINVAL;
    }
    std::string x(buf_x, len_x);
    std::string y(buf_y, len_y);
    std::string common = hirschberg(x, y);

    if (*len_result < common.size()) {
        return -ENOMEM;
    }

    *len_result = common.size();
    for (unsigned i = 0; i < *len_result; ++i) {
        result[i] = common[i];
    }

    return 0;
}

/**
 * C export of the hamming_klcs function above.
 */
int hamming_klcs_c(const char** seqs, size_t* seq_lens, size_t num_seqs, char* result, size_t* len_result)
{
    if (!len_result) {
        return -EINVAL;
    }
    std::vector< std::string > sequences;
    for (size_t i = 0; i < num_seqs; ++i) {
        sequences.push_back(std::string(seqs[i], seq_lens[i]));
    }
    
    std::string common = hamming_klcs(sequences);
    if (*len_result < common.size()) {
        return -ENOMEM;
    }

    for (size_t i = 0, e = common.size(); i < e; ++i) {
        result[i] = common[i];
    }
    *len_result = common.size();
    return 0;
}


static bool test_hirschberg() 
{
    std::string a = "vCyuyFjhK5lKOAMFzt2D3vF0kd5deNQqiXEAAGlVsFSGB8NtG9kou2fpOFoyIMS7r0b3L1xtE3fVYgfpcBt3HGGg4uJIkoX67B5BbkMCvVEcNalxzIzX7ad2Yn66nNbTJd3pprG6glEdYp7OWgOSFQX2yQp0Q6AdwozWOjv6nCa3LDIiryEFpun8QZiyakJJ9mW2BeNk";
    std::string b = "D50cSnvaoMSgSMa2IxDalzvljAMZI8eP2s6ZsGcpiAd3CxiiRua6mMetHhEeybp3N4Fvy24Ni8lX19uRSu5HHOeXQckvMb1lSuiJuUgDnpgF37mzxnd2HQIwAaxbtISeq2wSXXt0KBUbY78M6FSitsXM3OEPgA7BGWknRMfRl3pm5vdPIkaPPfDHnA7HShn0qrZ29DHg";
    std::string common = hirschberg(a, b);
    return common == "5M2Dvl82p3xtEp34vNlXbJgpgF2Q06AWn3pnZ2";
}

static bool test_hamming_klcs() {
    std::string a = "vCyuyFjhK5lKOAMFzt2D3vF0kd5deNQqiXEAAGlVsFSGB8NtG9kou2fpOFoyIMS7r0b3L1xtE3fVYgfpcBt3HGGg4uJIkoX67B5BbkMCvVEcNalxzIzX7ad2Yn66nNbTJd3pprG6glEdYp7OWgOSFQX2yQp0Q6AdwozWOjv6nCa3LDIiryEFpun8QZiyakJJ9mW2BeNk";
    std::string b = "D50cSnvaoMSgSMa2IxDalzvljAMZI8eP2s6ZsGcpiAd3CxiiRua6mMetHhEeybp3N4Fvy24Ni8lX19uRSu5HHOeXQckvMb1lSuiJuUgDnpgF37mzxnd2HQIwAaxbtISeq2wSXXt0KBUbY78M6FSitsXM3OEPgA7BGWknRMfRl3pm5vdPIkaPPfDHnA7HShn0qrZ29DHg";
    std::string c = "bIpMXSNIbcWYHWYb6XslfSrIAgUdSu2BRxDYLlFliMDVXre9Va6323Zw02MNRtwNucEEaXr1g8ToiikeahQFAYV9N7RsA1Xmezd5VnfIt3VnevpG3EF6ND18tbeKpnXP97feNapRRTBnhJuEiKk123ePmT7sRw5e2IeNlO2qqBGgI1p3T5PY0hSjP0iLQyLWqTwKlPc0";
    std::vector< std::string > seqs = {a, b, c};
    std::string common = hamming_klcs(seqs);  
    return common == "MNXSuM1gp3X73gW";

}

int main(int argc, char** argv) {
    if (test_hirschberg()) {
        std::cout << "Hirschberg: OK" << std::endl;
    }
    else {
        std::cout << "Hirschberg: ERROR" << std::endl;
    }
    if (test_hamming_klcs()) {
        std::cout << "hamming_klcs: OK" << std::endl;
    }
    else {
        std::cout << "hamming_klcs: ERROR" << std::endl;
    }

    return 0;
}
