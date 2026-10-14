import os
import re
import string
from functools import lru_cache
from typing import Pattern
import enchant

d = enchant.Dict("en_US")

def is_sequential_string(secret: str) -> bool:
    sequences = (
        # Base64 letters first
        (
                string.ascii_uppercase +
                string.ascii_uppercase +
                string.digits +
                '+/'
        ),

        # Base64 numbers first
        (
                string.digits +
                string.ascii_uppercase +
                string.ascii_uppercase +
                '+/'
        ),

        # We don't have a specific sequence for alphabetical
        # sequences, since those will happen to be caught by the
        # base64 checks.

        # Alphanumeric sequences
        (string.digits + string.ascii_uppercase) * 2,

        # Capturing any number sequences
        string.digits * 2,

        string.hexdigits.upper() + string.hexdigits.upper(),
        string.ascii_uppercase + '=/',
    )

    uppercase = secret.upper()
    for sequential_string in sequences:
        if uppercase in sequential_string:
            return True

    return False


def is_potential_uuid(secret: str) -> bool:
    return bool(_get_uuid_regex().search(secret))


@lru_cache(maxsize=1)
def _get_uuid_regex() -> Pattern:
    return re.compile(
        r'[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}',
        re.IGNORECASE,
    )


def is_likely_id_string(secret: str, line: str) -> bool:
    try:
        index = line.index(secret)
    except ValueError:
        return False

    return bool(_get_id_detector_regex().search(line, pos=0, endpos=index))


@lru_cache(maxsize=1)
def _get_id_detector_regex() -> Pattern:
    return re.compile(r'id[^\.a-z0-9]', re.IGNORECASE)


def is_non_text_file(filename: str) -> bool:
    _, ext = os.path.splitext(filename)
    return ext in IGNORED_FILE_EXTENSIONS


# We don't scan files with these extensions.
# Note: We might be able to do this better with
#       `subprocess.check_output(['file', filename])`
#       and look for "ASCII text", but that might be more expensive.
#
#       Definitely something to look into, if this list gets unruly long.
IGNORED_FILE_EXTENSIONS = set(
    (
        '.7z',
        '.bin',
        '.bmp',
        '.bz2',
        '.class',
        '.css',
        '.dmg',
        '.doc',
        '.eot',
        '.exe',
        '.gif',
        '.gz',
        '.ico',
        '.iml',
        '.ipr',
        '.iws',
        '.jar',
        '.jpg',
        '.jpeg',
        '.lock',
        '.map',
        '.mo',
        '.pdf',
        '.png',
        '.prefs',
        '.psd',
        '.rar',
        '.realm',
        '.s7z',
        '.sum',
        '.svg',
        '.tar',
        '.tif',
        '.tiff',
        '.ttf',
        '.webp',
        '.woff',
        '.xls',
        '.xlsx',
        '.zip',
        '.sln'
    ),
)


def is_templated_secret(secret: str) -> bool:
    """
    Filters secrets that are shaped like: {secret}, <secret>, or ${secret}.
    """
    try:
        if (
                (secret[0] == '{' and secret[-1] == '}')
                or (secret[0] == '<' and secret[-1] == '>')
                or (secret[0] == '$' and secret[1] == '{' and secret[-1] == '}')
        ):
            return True
    except IndexError:
        # Any one character secret (that causes this to raise an IndexError) is highly
        # likely to be a false positive (or if a true positive, INCREDIBLY weak password).
        return True

    return False


def is_prefixed_with_dollar_sign(secret: str) -> bool:
    # NOTE: This is broken out into its own function since it has more chance of increasing
    # false negatives than `is_templated_secret` (e.g. secrets that actually start with a $).
    # This is best used with files that actually use this as a means of referencing variables.
    # TODO: More intelligent filetype handling?
    #filenameCheck = filename.endswith("js") or filename.endswith("html") or filename.endswith("html")
    counter = (len(secret) - len(secret.replace("$",""))) / 1
    previousCheck = len(secret) > 0 and secret[0] == '$'
    return counter == 1 and previousCheck
    #return len(secret) > 0 and secret[0] == '$'


def is_indirect_reference(line: str) -> bool:
    """
    Filters secrets that take the form of:

        secret = get_secret_key()

    or

        secret = request.headers['apikey']
    """
    return bool(_get_indirect_reference_regex().search(line))


@lru_cache(maxsize=1)
def _get_indirect_reference_regex() -> Pattern:
    # Regex details:
    #   ([^\v=!:]*)     ->  Something before the assignment or comparison
    #   \s*             ->  Some optional whitespaces
    #   (:=?|[!=]{1,3}) ->  Assignment or comparison: :=, =, ==, ===, !=, !==
    #   \s*             ->  Some optional whitespaces
    #   (
    #       [\w.-]+     ->  Some alphanumeric character, dot or -
    #       [\[\(]      ->  Start of indirect reference: [ or (
    #       [^\v]*      ->  Something except line breaks
    #       [\]\)]      ->  End of indirect reference: ] or )
    #   )
    return re.compile(r'([^\v=!:]*)\s*(:=?|[!=]{1,3})\s*([\w.-]+[\[\(][^\v]*[\]\)])')


def is_lock_file(filename: str) -> bool:
    return os.path.basename(filename) in {
        'Brewfile.lock.json',
        'Cartfile.resolved',
        'composer.lock',
        'Gemfile.lock',
        'Package.resolved',
        'package-lock.json',
        'Podfile.lock',
        'yarn.lock',
        'Pipfile.lock',
    }


def is_not_alphanumeric_string(secret: str) -> bool:
    """
    This assumes that secrets should have at least ONE letter in them.
    This helps avoid clear false positives, like `*****`.
    """
    return not bool(set(string.ascii_letters) & set(secret))


def is_swagger_file(filename: str) -> bool:
    """
    Filters swagger files and paths, like swagger-ui.html or /swagger/.
    """
    return bool(_get_swagger_regex().search(filename))


@lru_cache(maxsize=1)
def _get_swagger_regex() -> Pattern:
    return re.compile(r'.*swagger.*')


keyList = [
    "zorunluluk", "anahtar", "yetkilendirme", "pasif",
    "fieldset", "keypress", "enter", "selfkey", "param", "error", "inputs", "requesturl", "usekeytab", "formheader",
    "formtype", "", "keyup", "backgroundcolor", "canvaslocation"
                "application", "organisation", "container", "title", "create", "question", "leader", "classes",
    "status", "timeout", "passive", "disabled", "alpha", "active", "event", "item", "id", "name", "step", "code", "fav",
    "number", "string", "object", "false", "true", "account", "undefined", "email", "serviceurl", "inline", "nodetype",
    "standard", "keyword", "instanceid", "password", "domain", "channelcode", "username", "definition", "hidden",
    "value", "security", "checked", "required", "organization", "listid", "systemparameterid", "turkcellsmspassword",
    "createautosearchkey", "wfdata",
                           "parentnode", "iscomedetailsearch", "language", "difficulty", "properties", "links",
    "operators", "outputs", "useragent", "log", "logout", "simple", "session", "searchkeys", "datalist", "ticketid",
    "actionid", "resourcelocation", "autoresponseid", "schedulejobid", "parserid", "exchangeid", "smsid", "templateid",
    "ruleid", "break", "abstract", "metatag", "definitionid", "searchkeyid", "emailtemplateid", "listid",
    "smstemplateid", "surveyid", "sladefinitionid", "customactionid", "actionscriptid", "searchqueryid",
    "workflowstatusid", "categoryid", "customactiondescriptionid", "integrationdataserviceid", "operationid", "roleid",
    "partyroleid", "rightid", "badgeid", "batchprocessid", "menuid", "systemmetaid", "sequenceid", "systemmessageid",
    "listenerid", "slatype", "grouptype", "supportleveltype", "shiftdefinitiontype", "workflowdefault", "ispars",
    "badwordid", "smartscreendocumentsget", "fineuploaderdnd", "clicks"
                                                               "yyyy", "yyyyy", "yyyyyy", "hmmss", "nnnnn", "ggggg",
    "shasymmetric",
    "kktcell", "trainingmethodtype", "personal", "trainingclass", "programcategory", "minseansdate", "quotaservice",
    "multiselectoptions", "trainingclass", "trainingtemplate", "traininginfocard", "remoteipaddress", "jboss",
    "storekey", ""
                "shitface", "fail", "turd", "shit", "hankey", "animal", "monkey", "nature", "haha", "omg", "padlock",
    "hundred", "border", "dummy",
    "userid", "companyid",
    "PBKDF2WithHmacSHA256", "HmacSHA256", "PBKDF2WithHmacSHA1"
]

encodingList = ['ascii', 'big5', 'big5hkscs', 'cp037', 'cp273', 'cp424', 'cp437', 'cp500', 'cp720', 'cp737', 'cp775',
                'cp850', 'cp852','cp855', 'cp856', 'cp857', 'cp858', 'cp860', 'cp861', 'cp862', 'cp863', 'cp864', 'cp865', 'cp866',
                'cp869', 'cp874', 'cp875', 'cp932', 'cp949', 'cp950', 'cp1006', 'cp1026', 'cp1125', 'cp1140', 'cp1250', 'cp1251', 'cp1252', 'cp1253', 'cp1254',
                'cp1255', 'cp1256', 'cp1257', 'cp1258', 'cp65001', 'euc-jp', 'euc-jis-2004', 'euc-jisx0213', 'euc-kr', 'gb2312', 'gbk', 'gb18030', 'hz',
                'iso2022-jp', 'iso2022-jp-1', 'iso2022-jp-2', 'iso2022-jp-2004', 'iso2022-jp-3', 'iso2022-jp-ext', 'iso2022-kr', 'latin-1', 'iso8859-2', 'iso8859-3',
                'iso8859-4', 'iso8859-5', 'iso8859-6', 'iso8859-7', 'iso8859-8', 'iso8859-9', 'iso8859-10', 'iso8859-11', 'iso8859-13', 'iso8859-14',
                'iso8859-15', 'iso8859-16', 'johab', 'koi8-r', 'koi8-t', 'koi8-u', 'kz1048', 'mac-cyrillic', 'mac-greek', 'mac-iceland', 'mac-latin2', 'mac-roman',
                'mac-turkish', 'ptcp154', 'shift-jis', 'shift-jis-2004', 'shift-jisx0213', 'utf-32', 'utf-32-be', 'utf-32-le', 'utf-16',
                'utf-16-be', 'utf-16-le', 'utf-7', 'utf-8', 'utf-8-sig']

def checkSplitData(secret: str, char: str):
    dataList = secret.split(char)
    size = len(dataList)
    counterNo = 0
    counterText = 0
    pattern1 = "[a-zA-Z]+"
    pattern2 = "[0-9]+"
    for data in dataList:
        result1 = re.search(pattern1, data)
        result2 = re.search(pattern2, data)
        if result1 is not None:
            counterText = counterText + 1
        if result2 is not None:
            counterNo = counterNo + 1

    return counterNo == size or counterText == size

def isExist(secret: str, char: str, limit: int):
    wordList = secret.split(char)
    count = 0
    for word in wordList:
        if any(word in x for x in keyList) or d.check(word):
            count = count + 1

    return count > limit - 1

def isExistByCapitalLetter(secret: str):
    list= re.findall('[A-Z][^A-Z]*', secret)
    size = len(list)
    count = 0
    if size > (len(secret) * 2 // 5) - 1:
        return False
    for word in list:
        if len(word) > 1 and d.check(word):
            count = count + 1

    return count > 0 and count > (size // 2)

def is_private_key(secret: str, line: str, filename: str) -> bool:
    list = ['BEGIN DSA PRIVATE KEY', 'BEGIN EC PRIVATE KEY', 'BEGIN OPENSSH PRIVATE KEY', 'BEGIN PGP PRIVATE KEY BLOCK', 'BEGIN PRIVATE KEY', 'BEGIN RSA PRIVATE KEY', 'BEGIN SSH2 ENCRYPTED PRIVATE KEY', 'PuTTY-User-Key-File-2']
    for txt in list:
        if txt in line:
            return True

def is_language_specific_string(secret: str, line: str, filename: str) -> bool:
    """
       This assumes that specific file type might contain different FP values
       """

    result = False
    lineLower = line.lower()
    filenameLower = filename.lower()
    secretLower = secret.lower()

    if filename.endswith(".config") and "<assemblyIdentity" in line and ("publicKeyToken=" in line or "<add key=" in lineLower):
        result = True
    if filenameLower.endswith(".config") and "<section name" in line:
        result = True
    if (filenameLower.endswith(".config") or filenameLower.endswith(".cs")) and (f"add key=\"{secret}\"" in lineLower or f"publickeytoken={secret}" in lineLower or f"publickeytoken=\"{secret}\"" in lineLower):
        result = True
    if filenameLower.endswith(".config") and ("<add name=\"ClientAuthenticationMembershipProvider\"".lower() in lineLower or "<add name=\"ClientRoleProvider\"".lower() in lineLower):
        result = True

    #IOS
    if (filenameLower.endswith(".storyboard")) \
            and (f"<color key=\"{secret}\"".lower() in lineLower or
                 f"<viewLayoutGuide key=\"{secret}\"".lower() in lineLower or
                 f"<point key=\"{secret}\"".lower() in lineLower or
                 f"<simulatedMetricsContainer key=\"{secret}\"".lower() in lineLower):
        result = True

    elif "https://github.com" in lineLower and "commit" in lineLower and f"commit/{secretLower}" in lineLower:
        result = True

    elif any(x in filenameLower for x in [".properties",".yaml"]) and any(x in secretLower for x in ["true", "yes", "on"]):
        result = True
    elif "123456789" in secret or ("ABCDEFG" in secret and ("KLMNOPR" in secret or "KLMNOPQ" in secret)):
        result = True
    elif "123456789" in secret or ("ABCDEFG".lower() in secret and ("KLMNOP".lower() in secret or "KLMNOPQ".lower() in secret)):
        result = True

    elif "PBKDF2WithHmacSHA256" in secret or "PBKDF2WithHmacSHA256".lower() in secretLower:
        result = True

    elif len(secret) < 5:
        result = True
    elif any(x in filenameLower for x in [".cs"]) and any(x in line for x in ["private const string DataTableTypeNameKey"]):
        result = True
    elif len(secret.split("_")) > 2 or isExist(secret, "_", 2):
        result = True
    #elif len(secret.split("-")) > 2 or isExist(secret, "-", 2):
    elif checkSplitData(secret, '-') > 2 or isExist(secret, "-", 2) or len(secret.split("-")) > 2:
        result = True
    elif len(secret.split(".")) > 2 or isExist(secret, ".", 2):
        result = True
    elif len(secret.split(":")) > 2 or isExist(secret, ":", 2):
        result = True
    elif len(secret.split("/")) > 2 or isExist(secret, "/", 2):
        result = True
    elif len(secret.split(",")) > 1 or isExist(secret, ",", 2):
        result = True
    elif len(secret.split(" ")) > 1 and not is_private_key(secret, line, filename):
        result = True
    elif (secret.endswith(".") and len(secret.split(" ")) > 1):
        result = True
    elif isExistByCapitalLetter(secret):
        result = True
    elif "author" in lineLower and len(lineLower.replace("author","").replace(secret,"").replace(" ","")) < 5:
        result = True
    # If it is been added this line or any(x in secret for x in keyList) to following line, 0 secret is found:
    elif secret in keyList or any(secret in x for x in keyList):
        result = True
    #Encoding handle
    elif secret in encodingList or secretLower in encodingList or any(secretLower in x for x in encodingList) or any(x in secretLower for x in encodingList):
        result = True
    elif secretLower.startswith("http://") or secretLower.startswith("https://"):
        result = True
    elif secretLower.endswith(".pdf"):
        result = True
    elif "\"bearer\"" in lineLower:
        result = True
    elif "(key)" in secretLower:
        result = True
    elif "\"authorization\"" in lineLower:
        result = True
    elif ("\"aes\"" in lineLower and "aes" in secret):
        result = True
    elif filenameLower.endswith(".java") and secretLower.endswith("dao"):
        result = True
    elif filenameLower.endswith(".java") and "gitVersion" in line and f"(\"gitVersion\", \"{secret}\")" in line:
        result = True
    elif filenameLower.endswith(".java") and line.strip().startswith("@XmlType("):
        result = True
    elif "readme.md" in filenameLower and f"\"sender\":\"{secret}\"" in line:
        result = True
    elif filenameLower.endswith(".cnf") and not f"\"{secret}\"" in line:
        result = True
    elif filenameLower.endswith(".xml") and (f"<entry key=\"{secret}\"" in lineLower or f"<prop key=\"{secret}\"" in lineLower):
        result = True
    elif secret.startswith("enc(") and secret.endswith(")"):
        result = True
    elif d.check(secret) or d.check(re.sub('[^a-zA-Z0-9 \n]', '', secret)):
        result = True
    elif "public static final String" in line:
        tmpData = line.replace("public static final String KEY_", "").replace("\t", "").replace("_", "").lower()
        if f"{secretLower} = \"{secretLower}\"" in tmpData:
            result = True
    else:
        lineLength = len(line)
        remaining = len(lineLower.replace(secret, ""))
        if (lineLength-remaining) // len(secret) > 1:
            result = True

    """if result is True:
        _tmp.insert("totalFP", _tmp.getAsInt("totalFP") + 1)"""

    return result