<?php

/*
$dir = new RecursiveDirectoryIterator('czdb_searcher_php/src/');
$iterator = new RecursiveIteratorIterator($dir);
foreach ($iterator as $fileinfo) {
    if ($fileinfo->isFile() && $fileinfo->getExtension() === 'php') {
        require_once $fileinfo->getPathname();
    }
}
*/

require_once __DIR__ . '/vendor/autoload.php';

use Czdb\Entity\DataBlock;
use Czdb\Entity\IndexBlock;
use Czdb\Utils\Decryptor;
use Czdb\Utils\HyperHeaderDecoder;

/**
 * CzdbIpExporter 类用于数据库搜索，支持内存搜索和B树搜索。
 */
class CzdbIpExporter {
    const SUPER_PART_LENGTH = 17;
    const FIRST_INDEX_PTR = 5;
    const END_INDEX_PTR = 13;
    const HEADER_BLOCK_PTR = 9;
    const FILE_SIZE_PTR = 1;

    private $dbType;
    private $ipBytesLength;
    private $totalHeaderBlockSize;
    private $raf;
    private $fileName;
    private $HeaderSip = [];
    private $HeaderPtr = [];
    private $headerLength;
    private $firstIndexPtr = 0;
    private $totalIndexBlocks = 0;
    private $dbBinStr = null;
    private $columnSelection = 0;
    private $geoMapData = null;
    private $headerSize = 0;
    private $toDir=null;
    private $oFiles=array();
    private $separator="\t";
 
    /**
     * 构造函数，初始化数据库搜索器。
     *
     * @param string $dbFile 数据库文件路径。
     * @param string $queryType 查询类型，支持 MEMORY 和 BTREE。
     * @param string $key 解密密钥。
     * @throws Exception 如果文件打开失败或IP格式错误。
     */
    public function __construct($dbFile, $key, $toDir, $s = "\t") {
        $this->fileName = $dbFile;
        $this->raf = fopen($dbFile, "rb");
        $headerBlock = HyperHeaderDecoder::decrypt($this->raf, $key);

        $offset = $headerBlock->getHeaderSize();
        $this->headerSize = $offset;

        fseek($this->raf, $offset);

        $superBytes = fread($this->raf, CzdbIpExporter::SUPER_PART_LENGTH);
        $superBytes = array_values(unpack("C*", $superBytes));

        $this->dbType = ($superBytes[0] & 1) == 0 ? 4 : 6;
        $this->ipBytesLength = $this->dbType == 4 ? 4 : 16;

        $this->loadGeoSetting($key);
        $this->initializeForMemorySearch();
        $this->toDir=$toDir;
        if(! empty($s)){
            $this->separator=$s;
        }
    }


    /**
     * 关闭数据库文件并释放资源。
     */
    public function close() {
        // Close file handle
        if (is_resource($this->raf)) {
            fclose($this->raf);
            $this->raf = null;
        }
        foreach ($this->oFiles as $of) {
            fclose($of);        
        }

        $this->oFiles=null;

        // Reset large data structures
        $this->dbBinStr = null;
        $this->HeaderSip = [];
        $this->HeaderPtr = [];
        $this->geoMapData = null;
    }

    /**
     * 比较两个字节序列。
     *
     * @param array $bytes1 第一个字节序列。
     * @param array $bytes2 第二个字节序列。
     * @param int $length 比较的长度。
     * @return int 返回比较结果：-1 表示 $bytes1 < $bytes2，1 表示 $bytes1 > $bytes2，0 表示相等。
     */
    private function compareBytes($bytes1, $bytes2, $length) {
        // unpack的数组下标从1开始
        for ($i = 1; $i <= $length; $i++) {
            $byte1 = $bytes1[$i];
            $byte2 = $bytes2[$i];

            if ($byte1 != $byte2) {
                // Compare based on byte values
                return $byte1 < $byte2 ? -1 : 1;
            }
        }
        // If all bytes are equal up to $length, return 0
        return 0;
    }

    /**
     * 内存搜索实现。
     *
     * @param array $regions 要导出ip的区域列表，如果为null，则导出所有ip。
     */
    public function export($regions) {
        $l = 0;
        $h = $this->totalIndexBlocks;

        $dataPtr = 0;
        $dataLen = 0;

        $blockLen = IndexBlock::getIndexBlockLength($this->dbType);

        while ($l <= $h) {
            $p = $this->firstIndexPtr + intval($l * $blockLen);
            $sip = unpack('C*', substr($this->dbBinStr, $p, $this->ipBytesLength));
            $eip = unpack('C*', substr($this->dbBinStr, $p + $this->ipBytesLength, $this->ipBytesLength));


            $dataPtr = unpack("L", substr($this->dbBinStr, $p + $this->ipBytesLength * 2, 4))[1];
            $dataLen = ord($this->dbBinStr[$p + $this->ipBytesLength * 2 + 4]);
            if ($dataPtr == 0) {
                continue;
            }
            $region = substr($this->dbBinStr, $dataPtr, $dataLen);
            $dataBlock=new DataBlock($region, $dataPtr);
            $this->writeToFile($sip,$eip,$dataBlock,$regions);
            $l++;
        }

    }

    private function writeToFile($sip,$eip,$dataBlock,$regions){
        if ($dataBlock == null) {
            return ;
        }
        $regionData = $dataBlock->getRegion($this->geoMapData, $this->columnSelection);
        $region="";
        $other="";

        // 按tab分割键和值
        $kv = explode("\t", $regionData, 2); // 限制为2部分，防止值中包含冒号
        if (count($kv) == 2) {
          $region = trim($kv[0]); // 去除空格
          $other = trim($kv[1]);
        }else{
            $region = trim($kv[0]);
        }

        if (empty($regions)) {
            $of=$this->oFiles["all"]; 
            if($of==null){
                print_r("open file ".$this->toDir."all-ip-list.txt to write.\n");
                $of=fopen($this->toDir."all-ip-list.txt", 'w');
                $this->oFiles["all"]=$of;
            }
            fwrite($of,$this->getIpFromBytes($sip).$this->separator.$this->getIpFromBytes($eip).$this->separator."$region".$this->separator.$other."\n");
            return;
        }
        foreach ($regions as  $key => $value) {
            if(strpos($region,$key)!==false){
                $of=$this->oFiles[$key];      
                if($of==null){
                    print_r("open file ".$this->toDir.$value."-ip-list.txt to write.\n");
                    $of=fopen($this->toDir.$value."-ip-list.txt", 'w');
                    if ($of === false) {
                        throw new Exception("failed to open file '%s'", $this->oDir.$value."-ip-list.txt");
                    }
                    $this->oFiles[$key]=$of;
                }
                fwrite($of,$this->getIpFromBytes($sip).$this->separator.$this->getIpFromBytes($eip).$this->separator."$region".$this->separator.$other."\n");
            }
        }      
    }

    private function getIpFromBytes($bytes){
        if (empty($bytes)){
            return null;
        }
        $packed = pack('C*', ...$bytes); // 'C*' 表示无符号字符序列

        // 步骤2：将二进制数据转换为可读的 IP 字符串
        $ip = inet_ntop($packed);
        return $ip;
    }

    /**
     * 将IP地址转换为字节序列。
     *
     * @param string $ip IP地址。
     * @return array 返回IP地址的字节序列。
     * @throws Exception 如果IP格式错误。
     */
    private function getIpBytes($ip) {
        if ($this->dbType == 4) {
            // For IPv4, use filter_var to validate and inet_pton to convert
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                throw new Exception("IP [$ip] format error for $this->dbType");
            }
            $ipBytes = inet_pton($ip);
        } else {
            // For IPv6, also use filter_var to validate and inet_pton to convert
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                throw new Exception("IP [$ip] format error for $this->dbType");
            }
            $ipBytes = inet_pton($ip);
        }
        return unpack('C*', $ipBytes);
    }



    /**
     * 加载地理位置映射表。
     *
     * @param string $key 解密密钥。
     */
    private function loadGeoSetting($key) {
        $this->fseek($this->raf, self::END_INDEX_PTR);
        $data = fread($this->raf, 4);
        $endIndexPtr = unpack('L', $data, 0)[1];

        $columnSelectionPtr = $endIndexPtr + IndexBlock::getIndexBlockLength($this->dbType);
        $this->fseek($this->raf, $columnSelectionPtr);
        $data = fread($this->raf, 4);
        $this->columnSelection = unpack('L', $data, 0)[1];

        if ($this->columnSelection == 0) {
            return;
        }

        $geoMapPtr = $columnSelectionPtr + 4;
        $this->fseek($this->raf, $geoMapPtr);
        $data = fread($this->raf, 4);
        $geoMapSize = unpack('L', $data, 0)[1];

        $this->fseek($this->raf, $geoMapPtr + 4);
        $this->geoMapData = fread($this->raf, $geoMapSize);

        $decryptor = new Decryptor($key);
        $this->geoMapData = $decryptor->decrypt($this->geoMapData);
    }

    /**
     * 为内存搜索初始化参数。
     * @throws Exception 如果文件大小不匹配。
     */
    private function initializeForMemorySearch() {
        $this->fseek($this->raf, 0);
        $fileSize = filesize($this->fileName) - $this->headerSize;
        $this->dbBinStr = fread($this->raf, $fileSize);

        $this->totalHeaderBlockSize = unpack('L', $this->dbBinStr, self::HEADER_BLOCK_PTR)[1];

        $fileSizeInFile = unpack('L', $this->dbBinStr, self::FILE_SIZE_PTR)[1];

        if ($fileSize != $fileSizeInFile) {
            throw new Exception("FileSize not match with the file");
        }

        $this->firstIndexPtr = unpack('L', $this->dbBinStr, self::FIRST_INDEX_PTR)[1];
        $lastIndexPtr = unpack('L', $this->dbBinStr, self::END_INDEX_PTR)[1];
        $this->totalIndexBlocks = (int) (($lastIndexPtr - $this->firstIndexPtr) / IndexBlock::getIndexBlockLength($this->dbType)) + 1;

        $headerBlockBytes = substr($this->dbBinStr, self::SUPER_PART_LENGTH, $this->totalHeaderBlockSize);
        $this->initHeaderBlock($headerBlockBytes, $this->totalHeaderBlockSize);
    }


    /**
     * 初始化头部块。
     *
     * @param string $headerBytes 头部块的字节序列。
     * @param int $size 头部块的大小。
     */
    private function initHeaderBlock($headerBytes, $size) {
        $indexLength = 20;

        $idx = 0;

        for ($i = 0; $i < $size; $i += $indexLength) {
            $dataPtrSegment = substr($headerBytes, $i + 16, 4);
            $dataPtr = unpack('L', $dataPtrSegment, 0)[1];

            if ($dataPtr === 0) {
                break;
            }

            $this->HeaderSip[$idx] = unpack('C*', substr($headerBytes, $i, 16));
            $this->HeaderPtr[$idx] = $dataPtr;
            $idx++;
        }

        $this->headerLength = $idx;
    }

    /**
     * 移动文件指针
     *
     * @param resource $handler 文件句柄。
     * @param int $offset 偏移量。
     */
    private function fseek($handler, $offset) {
        fseek($handler, $this->headerSize + $offset);
    }
}


function parse_regions($regions){
   $map = [];

   if (empty($regions)) {
        return $map;
    }

    // 按分号分割成键值对
    $pairs = explode(',', $regions);

    foreach ($pairs as $pair) {
        if (empty($pair)){
            continue;
        }
        // 按冒号分割键和值
        $kv = explode(':', $pair, 2); // 限制为2部分，防止值中包含冒号
        if (count($kv) == 2) {
          $key = trim($kv[0]); // 去除空格
          $value = trim($kv[1]);
          $map[$key] = $value;
        }else{
            $key = trim($kv[0]);
            $map[$key] = $key;
        }
    }
    return $map;
}

function usage(){
  echo "用法: php czdb_ip_exporter.php -k [纯真ip数据库密钥,必须参数，需要到纯真网站申请] -d [czdb文件，必须指定。] -r [导出的区域列表，逗号分隔,没指定为导出所有数据。如：\"杭州:HZ,台州:TZ,浙江\" 。其中\":\"后面部分是区域输出文件前缀缩写，如果不指定则直接以区域名输出] -o [输出ip列表目标路径，默认当前工作目录] -s [输出文本文件的分隔符，默认tab\n";
  exit();   
}

$options = getopt('hk:d:o:r:s:');
if(isset($options['h'])){
    usage();
}

$optionsD=null;

if(isset($options['d'])){
  $optionD = $options['d'];
}

if (!is_readable($optionD)) {
    echo "IP数据库文件".$optionD."不存在或不可读。\n";
    usage();
}

if(isset($options['r'])){
  $optionR = $options['r'];
}


if(isset($options['k'])){
  $optionK = $options['k'];
}

if (empty($optionK)){
    echo "纯真ip数据库密钥为空，必须指定密钥。\n";
    usage();
}

$regions=parse_regions($optionR);


if(isset($options['o'])){
  $optionO = $options['o'];
}

if(empty($optionO)){
    $optionO=".";
}

if(isset($options['s'])){
  $optionS = $options['s'];
}

$exporter= new czdbIpExporter($optionD,$optionK,$optionO,$optionS);
$exporter->export($regions);
$exporter->close();

?>