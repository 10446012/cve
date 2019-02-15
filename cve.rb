require 'oga'
require 'net/http'
require 'csv'
require 'logger'
year = "2019"
filename="CVE_" + year
#----------- cve list ----------
listurl = Net::HTTP.get(URI.parse("https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=" + year))
listdoc = Oga.parse_html(listurl)
all = []
list = []
finallist = []
nistlink = []
pages = []
trid = []
y = 0

listdoc.css('div#TableWithRules table tr td').each do |link|
  all << link.text
  if y.odd?
    list << all[0].split('-')[2] unless all[1].include?("** RESERVED **") || all[0].split('-')[1] != year
    all.clear
  end
  y = y + 1
end
nistsearch = Net::HTTP.get(URI.parse("https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=CVE-"+ year +"-&search_type=all"))
nistlist = Oga.parse_html(nistsearch)
nistlist.xpath('//nav/ul/li/a/@href').each do |link|
  nistlink << link.text
end
nistlink  = nistlink.uniq
counter = 0
while counter <= nistlink.last.split("=").last.to_i
  pages << counter
  counter += 20
end

for page in pages
  search = Net::HTTP.get(URI.parse( "https://nvd.nist.gov" + nistlink.first.split("startIndex")[0] + "startIndex=" + page.to_s  ))
  final = Oga.parse_html(search)
  final.css('div tbody tr').each do |link|
    trid << link.text.split("\r\n")[2].gsub(' ','').split("-")[2] if link.text.include?("(not available)")
  end
end
finallist = list - trid
#----------- nist ----------
times = 0
CSV.open("#{filename.gsub(".","_")}.csv", "wb") do |csv|
  csv << ["CVE-ID", "AV", "AC", "PR", "UI", "S", "C", "I", "A", "Score", "Description","POC"]
  for id in finallist
    time = Time.now.to_i
    url = Net::HTTP.get(URI.parse("https://nvd.nist.gov/vuln/detail/CVE-"+ year +"-" + id))
    doc = Oga.parse_html(url)
    impact=[]
    score = []
    cvss = []
    hyperlink = []
    description = []
    poc = []
    des = []
    cveid = []
    x=1

    doc.css('div#p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView_VulnHyperlinksPanel table tr td').each do |link|
      hyperlink << link.text
    end
    0.upto(hyperlink.count/2-1) do |i|
      if hyperlink[i+x].include?("Exploit")
        poc <<  hyperlink[i+x-1]
      else
        poc << hyperlink[i+x-1] if hyperlink[i+x-1].include?("exploit")
      end
      x = x + 1
    end

    unless poc.empty?
      doc.css('div#p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView_Vuln3CvssPanel p span').each do |link|
        impact << link.text
      end
      unless impact.empty?
        impact[2].split("(")[0].split('/').each do |z|
          cvss << z.split(':')[1].chomp
        end
        doc.css('table#p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView tr td div p').each do |link|
          description << link.text
        end
        if description[0].include?("This vulnerability has been modified since it was last analyzed by the NVD. It is awaiting reanalysis which may result in further changes to the information provided")
          des << description[1]
        else
          des << description[0]
        end
        unless cvss.empty?
          cveid << "=HYPERLINK(\"https://nvd.nist.gov/vuln/detail/CVE-2019-"+ id + "\"" +",\"2019-" + id + "\"" + ")"
          score << impact[0].gsub!(' ','')
          csv << cveid + cvss + score + des + poc
        end
      end
    end
    times = times + ( Time.now.to_i - time )
    puts (Time.now.to_i - time).to_s + "s-" +id
  end
end

puts "took" + times.to_s + "sec"
