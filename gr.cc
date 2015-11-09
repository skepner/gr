#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <string>
#include <cstring>
#include <stack>
#include <forward_list>
#include <regex>
#include <list>
#include <vector>

#include <sys/types.h>
#include <dirent.h>

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <bzlib.h>

// ----------------------------------------------------------------------

typedef long offset_t;

struct MatchInfo
{
    inline MatchInfo(offset_t f, offset_t l) : first(f), last(l) {}
    inline void assign(offset_t f, offset_t l) { first = f; last = l; }
    offset_t first;               // relative to line beginning
    offset_t last;                // relative to line beginning
};

struct MatchingLineInfo
{
    offset_t no;
    offset_t first;
    offset_t last;       // offset of '\n' or EOF
    std::list<MatchInfo> matches;
};

// ----------------------------------------------------------------------

class Output
{
 public:
    inline Output()
        : mExitCode(0), mLines(0),
          startColor("\x1B[35;47m"), resetColor("\x1B[0m"),
          mLongLineThreshold(200), mFirstMatchOffsetThreshold(100), mFirstMatchOffsetIndent(10), mAfterLastMatchThreshold(30)
        {
        }

    inline void error(const std::string& aFilename, const std::string& aError)
        {
            std::cerr << aFilename << ": error: " << aError << std::endl;
            mExitCode = 1;
        }

    void message(const std::string& aFilename, offset_t aLineNo, offset_t aColumnNo, const char* aText, offset_t aSize, const std::list<MatchInfo>& aHighlight);

    void binary_file_matches(const std::string& aFilename);

    inline int exit_code()
        {
            if (mExitCode == 0 && mLines == 0)
                mExitCode = 2;
            return mExitCode;
        }

 private:
    int mExitCode;
    int mLines;
    const char* startColor;
    const char* resetColor;
    offset_t mLongLineThreshold;
    offset_t mFirstMatchOffsetThreshold;
    offset_t mFirstMatchOffsetIndent;
    offset_t mAfterLastMatchThreshold;
};

void Output::message(const std::string& aFilename, offset_t aLineNo, offset_t aColumnNo, const char* aText, offset_t aSize, const std::list<MatchInfo>& aHighlight)
{
    std::cout << aFilename << ':' << aLineNo << ':' << aColumnNo << ':';
    offset_t start = 0, left = aSize;
    if (aSize > mLongLineThreshold && aHighlight.front().first > mFirstMatchOffsetThreshold) {
        std::cout << "<<<";
        start = std::min(aHighlight.front().first - mFirstMatchOffsetIndent, aSize - mFirstMatchOffsetThreshold);
        left -= start;
    }
    const offset_t real_start = start;
    for (auto match: aHighlight) {
        std::cout.write(aText + start, match.first - start);
        std::cout << startColor;
        std::cout.write(aText + match.first, match.last - match.first);
        std::cout << resetColor;
        start = match.last;
        left = aSize - start;
    }
    if ((aSize - real_start) > mLongLineThreshold && (aSize - start) > mAfterLastMatchThreshold) {
        std::cout.write(aText + start, mAfterLastMatchThreshold);
        std::cout << ">>>";
    }
    else {
        std::cout.write(aText + start, left);
    }
    std::cout << std::endl;
    ++mLines;
}

void Output::binary_file_matches(const std::string& aFilename)
{
    std::cout << aFilename << ":1:1: binary file matches" << std::endl;
    ++mLines;
}

// ----------------------------------------------------------------------

class Options
{
 public:
    inline Options()
        : mFilenamesToIgnore("^(build|dist|\\.cabal.*|.*\\.(html|docx?|xlsx?|o|py[oc]|git|gitignore|so[\\.0-9]*|a|dylib|libs|exe|ilk|obj|pch|pdb|idb|fasl)(\\.(bz2|gz|xz))?)$", std::regex::icase),
          mLineLengthThreshold(100), mFilenameForStdin("*stdin*")
        {
        }

    inline std::regex::flag_type regex_flags() const
        {
            return std::regex::icase;
        }

    inline bool ignore_filename(const std::string& aFilename) const
        {
            return std::regex_match(aFilename, mFilenamesToIgnore);
        }

    inline offset_t lineLengthThreshold() const { return mLineLengthThreshold; }

    inline std::string filename_for_stdin() const { return mFilenameForStdin; }

 private:
    std::regex mFilenamesToIgnore;
    offset_t mLineLengthThreshold;
    std::string mFilenameForStdin;
};

// ======================================================================

enum class FileType { Stdin, Regular, Directory, Excluded, Other };

struct NameEntry
{
    std::string name;
    offset_t size;
    FileType file_type;
    std::string error;
};

// ----------------------------------------------------------------------

class NameListB
{
 public:
    inline NameListB(Output& aOutput) : mOutput(aOutput) {}
    virtual inline ~NameListB() {}

    const NameEntry& get() const;
    void next();

    virtual bool at_end() const = 0;

 protected:
    inline Output& output() { return mOutput; }
    inline NameEntry& entry() { return mCurrent; }

    virtual void advance() = 0;

    void expand_current();
    virtual void get_entry() = 0;
    virtual void stat_to_entry();

 private:
    Output &mOutput;
    NameEntry mCurrent;

    bool expand();
};

inline const NameEntry& NameListB::get() const
{
    if (at_end())
        throw std::runtime_error("NameList exhausted");
    return mCurrent;
}

inline void NameListB::next()
{
    advance();
    expand_current();
}


inline void NameListB::expand_current()
{
    while(!at_end() && expand())
        advance();
}

void NameListB::stat_to_entry()
{
    struct stat buf;
    if (stat(entry().name.c_str(), &buf)) {
        entry().file_type = FileType::Other;
        entry().error = std::strerror(errno);
    }
    else {
        switch (buf.st_mode & S_IFMT) {
          case S_IFREG:
              entry().size = static_cast<offset_t>(buf.st_size);
              entry().file_type = FileType::Regular;
              break;
          case S_IFDIR:
              entry().file_type = FileType::Directory;
              break;
          default:
              entry().file_type = FileType::Other;
              switch (buf.st_mode & S_IFMT) {
                case S_IFIFO:
                    entry().error = "named pipe";
                    break;
                case S_IFCHR:
                    entry().error = "character special";
                    break;
                case S_IFBLK:
                    entry().error = "block special";
                    break;
                case S_IFLNK:
                    entry().error = "symbolic link";
                    break;
                case S_IFSOCK:
                    entry().error = "socket";
                    break;
                // case S_IFWHT:
                //     entry().error = "whiteout";
                //     break;
                default:
                    entry().error = "unknown";
                    break;
              }
              break;
        }
    }
}

bool NameListB::expand()
{
    bool skip = false;
    get_entry();
    switch (entry().file_type) {
      case FileType::Regular:
          skip = entry().size == 0;
          break;
      case FileType::Stdin:
          break;
      case FileType::Directory:
          break;
      case FileType::Excluded:
          skip = true;
          break;
      case FileType::Other:
          mOutput.error(entry().name, entry().error);
          skip = true;
          break;
    }
    return skip;
}

template <typename InputIterator> class NameList : public NameListB
{
 public:
    inline NameList(InputIterator first, InputIterator last, Output& aOutput)
        : NameListB(aOutput), mCurrent(first), mLast(last)
        {
            expand_current();
        }

    virtual inline bool at_end() const
        {
            return mCurrent == mLast;
        }

 protected:
    virtual void advance()
        {
            if (!at_end())
                ++mCurrent;
        }

    virtual void get_entry();

 private:
    InputIterator mCurrent;
    InputIterator mLast;
};

template <typename InputIterator> void NameList<InputIterator>::get_entry()
{
    if (at_end())
        throw std::runtime_error("NameList exhausted");
    entry().name = *mCurrent;
    if (entry().name == "-") {
        entry().file_type = FileType::Stdin;
    }
    else {
        stat_to_entry();
    }
}

// ----------------------------------------------------------------------

class Directory : public NameListB
{
 public:
    Directory(const std::string& aPath, Output& aOutput, const Options& aOptions);
    virtual ~Directory();

 protected:
    virtual void advance();
    virtual bool at_end() const;
    virtual void get_entry();

 private:
    std::string mPath;
    DIR* mDir;
    dirent* mCurrent;
    const Options& mOptions;
};

Directory::Directory(const std::string& aPath, Output& aOutput, const Options& aOptions)
    : NameListB(aOutput), mPath(aPath), mDir(opendir(mPath.c_str())), mCurrent(nullptr), mOptions(aOptions)
{
    while (mPath.back() == '/') // remove trailing slashes to make resulting filepath look better
        mPath.pop_back();
    if (mDir == nullptr) {
        output().error(mPath, std::strerror(errno));
    }
    else {
        advance();
        expand_current();
    }
}

Directory::~Directory()
{
    if (mDir != nullptr)
        closedir(mDir);
}

void Directory::advance()
{
    mCurrent = readdir(mDir);
}

bool Directory::at_end() const
{
    return mCurrent == nullptr;
}

void Directory::get_entry()
{
    const std::string name(mCurrent->d_name
#ifdef __APPLE__
                           , mCurrent->d_namlen
#endif
                           );
    if (name == "." || name == ".." || mOptions.ignore_filename(name)) {
        entry().name = name;
        entry().file_type = FileType::Excluded;
    }
    else {
        entry().name = mPath + "/" + name;
        entry().file_type = FileType::Other;
        switch (mCurrent->d_type) {
          case DT_FIFO:
              entry().error = "named pipe";
              break;
          case DT_CHR:
              entry().error = "character special";
              break;
          case DT_DIR:
              entry().file_type = FileType::Directory;
              break;
          case DT_BLK:
              entry().error = "block special";
              break;
          case DT_REG:
              stat_to_entry(); // need to get size
              break;
          case DT_LNK:
              stat_to_entry(); // need to expand link
              break;
          case DT_SOCK:
              entry().error = "socket";
              break;
          case DT_WHT:
              entry().error = "whiteout";
              break;
          case DT_UNKNOWN:
          default:
              entry().error = "unknown";
              break;
        }
    }
}

// ======================================================================

class FileScanner;

class FileScannerIterator
{
 public:
    const NameEntry& operator*() const;
    FileScannerIterator& operator++();
          // FileScannerIterator operator++(int);

    friend bool operator==(const FileScannerIterator& x, const FileScannerIterator& y);
    friend inline bool operator!=(const FileScannerIterator& x, const FileScannerIterator& y) { return !(x == y); }

 private:
    friend class FileScanner;
    FileScanner* mParent;

    explicit FileScannerIterator(FileScanner* aParent);
    bool check_stack(); // returns if NameListB* was poppped from stack
    bool expand();      // returns if current entry must be skipped
    bool eq(const FileScannerIterator &it) const;
};

// ----------------------------------------------------------------------

class FileScanner
{
 public:
    template<typename InputIt> inline FileScanner(InputIt first, InputIt last, Output& aOutput, const Options& aOptions)
        : mOutput(aOutput), mOptions(aOptions)
        {
            if (first == last) {
                static const char* argv[] = {"-"};
                mStack.push(std::make_shared<NameList<const char**>>(argv, argv + 1, mOutput));
            }
            else
                mStack.push(std::make_shared<NameList<InputIt>>(first, last, mOutput));
        }

    inline FileScannerIterator begin() { return FileScannerIterator(this); }
    inline FileScannerIterator end() { return FileScannerIterator(nullptr); }

    inline void push_directory(const std::string& aPath)
        {
            mStack.push(std::make_shared<Directory>(aPath, mOutput, mOptions));
        }

 private:
    friend class FileScannerIterator;
    Output& mOutput;
    const Options& mOptions;
    std::stack<std::shared_ptr<NameListB>> mStack;
};

// ----------------------------------------------------------------------

FileScannerIterator::FileScannerIterator(FileScanner* aParent)
    : mParent(aParent)
{
    if (mParent != nullptr) {
        check_stack(); // check if there are any not filtered files in the scanner initially
    }
    if (mParent != nullptr && expand()) {
        operator++(); // skip initial entry
    }
}

inline const NameEntry& FileScannerIterator::operator*() const
{
    return mParent->mStack.top()->get();
}

FileScannerIterator& FileScannerIterator::operator++()
{
    if (mParent != nullptr) {
        auto& stack = mParent->mStack;
        bool skip = true;
        while (skip && mParent != nullptr) {
            stack.top()->next();
            if (! check_stack()) {
                skip = expand();
            }
        }
    }
    return *this;
}

bool FileScannerIterator::check_stack()
{
    bool popped = false;
    auto& stack = mParent->mStack;
    if (stack.top()->at_end()) {
        stack.pop();
        popped = true;
        if (stack.empty()) {
            mParent = nullptr;
        }
    }
    return popped;
}

bool FileScannerIterator::expand()
{
    bool skip = false;
    auto& current = mParent->mStack.top()->get();
    switch (current.file_type) {
      case FileType::Regular:
          skip = mParent->mOptions.ignore_filename(current.name);
          break;
      case FileType::Stdin:
            //std::cout << "STDIN" << std::endl;
          break;
      case FileType::Directory:
          mParent->push_directory(current.name);
            // pushed directory may contain no not filtered entries -> check_stack()
          skip = check_stack() || expand();
          break;
      case FileType::Excluded:
      case FileType::Other:
            // actually, should never come here
          mParent->mOutput.error(current.name, "internal in FileScanner::iterator::expand");
          skip = true;
          break;
    }
    return skip;
}

inline bool operator==(const FileScannerIterator& x, const FileScannerIterator& y)
{
    return x.eq(y);
}

inline bool FileScannerIterator::eq(const FileScannerIterator &it) const
{
    return mParent == it.mParent && (mParent == nullptr || mParent->mStack.top() == it.mParent->mStack.top());
}

// ======================================================================

class FileSearch
{
 public:
    virtual ~FileSearch();
    virtual void search(const std::regex& aRegex, const std::string& aFilename, Output& aOutput) const = 0;
};


FileSearch::~FileSearch()
{
}

// ----------------------------------------------------------------------

class FileSearchBuffer :  public FileSearch
{
 public:
    inline FileSearchBuffer() : mNewLine('\n') {}

    virtual void search(const std::regex& aRegex, const std::string& aFilename, Output& aOutput) const;

    virtual const char* buffer() const = 0;
    virtual offset_t buffer_size() const = 0;

 protected:
    void line_of(offset_t aOffset, MatchingLineInfo& aMatchingLineInfo) const;
    void output(const std::string& aFilename, const MatchingLineInfo& aLine, Output& aOutput) const;
    bool check_binary(const char* start, const char* end) const;

 private:
    char mNewLine;
};

void FileSearchBuffer::search(const std::regex& aRegex, const std::string& aFilename, Output& aOutput) const
{
    const char* start = buffer();
    const char* end = buffer() + buffer_size();
    bool binary = check_binary(start, end);
    std::cmatch match;
    while (start < end && std::regex_search(start, end, match, aRegex)) {
        if (binary) {
            aOutput.binary_file_matches(aFilename);
            break;
        }
        else {
            MatchingLineInfo line;
            line_of(match[0].first - buffer(), line);
            const char* const line_start = buffer() + line.first;
            MatchInfo match_info(match[0].first - line_start, match[0].second - line_start);
            line.matches.push_back(match_info);
            bool found_again = true;
            while (found_again) {
                const char* start_again = buffer() + line.first + match_info.last;
                found_again = start_again < (buffer() + line.last) && std::regex_search(start_again, buffer() + line.last, match, aRegex);
                if (found_again) {
                    match_info.assign(match[0].first - line_start, match[0].second - line_start);
                    line.matches.push_back(match_info);
                    start_again += match_info.last;
                }
            }
            start = buffer() + line.last + 1;
            output(aFilename, line, aOutput);
        }
    }
}

void FileSearchBuffer::line_of(offset_t aOffset, MatchingLineInfo& aLineInfo) const
{
    const char* start = buffer();
    const char* offset_p = start + aOffset;
    offset_t size = buffer_size();

    for (aLineInfo.last = 0, aLineInfo.no = 0; aLineInfo.last == 0; ++aLineInfo.no) {
        const char* found = static_cast<const char*>(std::memchr(start, mNewLine, static_cast<size_t>(size)));
        if (found == nullptr) {
            aLineInfo.first = start - buffer();
            aLineInfo.last = buffer_size();
        }
        else {
            if (found >= offset_p) {
                aLineInfo.first = start - buffer();
                aLineInfo.last = found - buffer();
            }
            else {
                size -= found - start + 1;
                start = found + 1;
            }
        }
    }
}

void FileSearchBuffer::output(const std::string& aFilename, const MatchingLineInfo& aLine, Output& aOutput) const
{
    aOutput.message(aFilename, aLine.no, aLine.matches.front().first + 1, buffer() + aLine.first, aLine.last - aLine.first, aLine.matches);
}

bool FileSearchBuffer::check_binary(const char* start, const char* end) const
{
    bool binary = false;
    for (offset_t off = 0; !binary && off < 100 && start < end; ++start, ++off) {
        const unsigned char c = static_cast<unsigned char>(*start);
        binary |= c < ' ' && c != '\n' && c != '\r' && c != '\t';
    }
    return binary;
}

// ----------------------------------------------------------------------

class FileSearchMmap : public FileSearchBuffer
{
 public:
    inline FileSearchMmap(std::string aFilename, offset_t aSize)
        : mSize(aSize), mData(nullptr)
        {
            mFd = open(aFilename.c_str(), O_RDONLY);
            if (mFd < 0)
                throw std::runtime_error(std::strerror(errno));
            mData = static_cast<const char*>(mmap(nullptr, static_cast<size_t>(mSize), PROT_READ, MAP_PRIVATE, mFd, 0));
            if (mData == MAP_FAILED)
                throw std::runtime_error(std::strerror(errno));
        }

    virtual ~FileSearchMmap();

    virtual inline const char* buffer() const { return mData; }
    virtual inline offset_t buffer_size() const { return mSize; }

 private:
    offset_t mSize;
    const char* mData;
    int mFd;
};

FileSearchMmap::~FileSearchMmap()
{
    if (mData)
        munmap(static_cast<void*>(const_cast<char*>(mData)),  static_cast<size_t>(mSize));
    if (mFd >= 0)
        close(mFd);
}

// ----------------------------------------------------------------------

class FileSearchBzip2 : public FileSearchBuffer
{
 public:
    FileSearchBzip2(const char* buffer, offset_t size);
    virtual ~FileSearchBzip2();

    virtual inline const char* buffer() const { return mData.data(); }
    virtual inline offset_t buffer_size() const { return static_cast<offset_t>(mData.size()); }

    static bool bzipped(const char* buffer, offset_t size);

 private:
    std::vector<char> mData;

    class Bzip2Decompressor
    {
     public:
        inline Bzip2Decompressor(const char* input, offset_t size)
            {
                mStream.bzalloc = nullptr;
                mStream.bzfree = nullptr;
                mStream.next_in = const_cast<char*>(input);
                mStream.avail_in = static_cast<unsigned int>(size);
                const int bz_error = BZ2_bzDecompressInit(&mStream, 0, 0);
                if (bz_error != BZ_OK) {
                    std::cerr << "bzip error : " << bz_error << std::endl;
                    throw std::runtime_error("Bzip2 init error");
                }
            }

        inline ~Bzip2Decompressor()
            {
                BZ2_bzDecompressEnd(&mStream);
            }

        inline bz_stream& stream() { return mStream; }

     private:
        bz_stream mStream;
    };
};

FileSearchBzip2::~FileSearchBzip2()
{
}

bool FileSearchBzip2::bzipped(const char* buffer, offset_t size)
{
    return size > 10 && !std::memcmp(buffer, "BZh", 3) && !std::memcmp(buffer + 4, "\x31\x41\x59\x26\x53\x59", 6);
}

FileSearchBzip2::FileSearchBzip2(const char* buffer, offset_t size)
{
    const offset_t CHUNK_SIZE = 1024 * 102;

    if (size > 0xFFFFFFFF)
        throw std::runtime_error("source is too big (>4Gb)");

    Bzip2Decompressor bz(buffer, size);

    offset_t output_size = 0;
    mData.resize(CHUNK_SIZE);
    bz.stream().next_out = mData.data();
    bz.stream().avail_out = static_cast<unsigned int>(mData.size());

    while (bz.stream().avail_in > 0) {
        const char* const this_out = bz.stream().next_out;
        int bz_error = BZ2_bzDecompress(&bz.stream());
        switch (bz_error) {
          case BZ_OK:
          case BZ_RUN_OK:
          case BZ_FLUSH_OK:
          case BZ_FINISH_OK:
              output_size += bz.stream().next_out - this_out;
              if (bz.stream().avail_in > 0 && bz.stream().avail_out == 0) {
                  mData.resize(mData.size() + CHUNK_SIZE);
                  bz.stream().next_out = mData.data() + output_size;
                  bz.stream().avail_out = static_cast<unsigned int>(static_cast<offset_t>(mData.size()) - output_size);
              }
              break;
          case BZ_STREAM_END:
              output_size += bz.stream().next_out - this_out;
              bz.stream().avail_in = 0;  // done
              break;
          default:
              std::cerr << "bzip error : " << bz_error << std::endl;
              throw std::runtime_error("Bzip2 error");
        }
    }
    mData.resize(static_cast<size_t>(output_size));
}

// ----------------------------------------------------------------------

class FileSearchStdin : public FileSearch
{
 public:
    inline FileSearchStdin(std::string aFilename) : mFilename(aFilename) {}
    virtual void search(const std::regex& aRegex, const std::string& aFilename, Output& aOutput) const;

 private:
    std::string mFilename;
};

void FileSearchStdin::search(const std::regex& aRegex, const std::string& /*aFilename*/, Output& aOutput) const
{
    std::string buffer;
    std::smatch match;
    for (offset_t line_no = 1; std::getline(std::cin, buffer); ++line_no) {
        if (std::regex_search(buffer, match, aRegex)) {
            const offset_t line_length = static_cast<offset_t>(buffer.length());
            MatchingLineInfo line {line_no, 0, line_length, std::list<MatchInfo>()};
            MatchInfo match_info(match[0].first - buffer.begin(), match[0].second - buffer.begin());
            line.matches.push_back(match_info);
            bool found_again = true;
            std::string::const_iterator end = buffer.end();
            while (found_again) {
                std::string::const_iterator start_again = buffer.begin() + match_info.last;
                found_again = std::regex_search(start_again, end, match, aRegex);
                if (found_again) {
                    match_info.assign(match[0].first - buffer.begin(), match[0].second - buffer.begin());
                    line.matches.push_back(match_info);
                    start_again += match_info.last;
                }
            }
            aOutput.message(mFilename, line.no, line.matches.front().first + 1, buffer.c_str(), line_length, line.matches);
        }
    }
}

// ----------------------------------------------------------------------

std::shared_ptr<FileSearch> open_file(const std::string& aFilename, offset_t aSize, const Options& aOptions);

std::shared_ptr<FileSearch> open_file(const std::string& aFilename, offset_t aSize, const Options& aOptions)
{
    std::shared_ptr<FileSearch> f2;
    if (aFilename == "-") {
        f2 = std::make_shared<FileSearchStdin>(aOptions.filename_for_stdin());
    }
    else {
        auto f1 = std::make_shared<FileSearchMmap>(aFilename, aSize);
        f2 = f1;
        if (FileSearchBzip2::bzipped(f1->buffer(), f1->buffer_size())) {
            f2 = std::make_shared<FileSearchBzip2>(f1->buffer(), f1->buffer_size());
        }
    }
    return f2;
}

// ----------------------------------------------------------------------

class Grep
{
 public:
    // inline Grep(const std::string& aRegex, const std::string& aFilename, offset_t aFileSize, Output& aOutput, const Options& aOptions)
    //     : mRegex(aRegex, aOptions.regex_flags()), mFilename(aFilename), mFileSize(aFileSize), mOutput(aOutput)//, mOptions(aOptions)
    //     {
    //     }

    inline Grep(const std::regex& aRegex, const std::string& aFilename, offset_t aFileSize, Output& aOutput, const Options& aOptions)
        : mRegex(aRegex), mFilename(aFilename), mFileSize(aFileSize), mOutput(aOutput), mOptions(aOptions)
        {
        }

    inline ~Grep()
        {
        }

    inline void search()
        {
            try {
                std::shared_ptr<FileSearch> file(open_file(mFilename, mFileSize, mOptions));
                file->search(mRegex, mFilename, mOutput);
            }
            catch (std::exception& err) {
                mOutput.error(mFilename, err.what());
            }
        }

 private:
    std::regex mRegex;
    std::string mFilename;
    offset_t mFileSize;
    Output& mOutput;
    const Options& mOptions;
};

// ======================================================================

int main(int argc, const char** argv)
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <regex> [filename or dirname] ..." << std::endl;
        return 1;
    }

    Output output;
    try {
        Options options;
        FileScanner scanner(argv + 2, argv + argc, output, options);

        try {
            std::regex re(std::regex(argv[1], options.regex_flags()));
            for (auto name: scanner) {
                  // std::cout << name.name << std::endl;
                Grep grep(re, name.name, name.size, output, options);
                grep.search();
            }
        }
        catch (std::regex_error& err) {
            output.error(argv[1], err.what());
        }
    }
    catch (std::exception& err) {
        output.error("ERROR", err.what());
    }
    return output.exit_code();
}

// ----------------------------------------------------------------------
