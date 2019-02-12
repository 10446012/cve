require 'nokogiri' # 解析html gem
require 'open-uri' # 用來打開網頁的工具


#----------- cve list ----------
listurl = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=2019"
listdoc = Nokogiri::HTML(open(listurl))
all = []
list = []
y = 1 

listdoc.css('div#TableWithRules table tr td').each do |link|
  all << link.content
end

0.upto(all.count/2-1) do |i| 
  list << all[y+i-1].split('-')[2] unless all[y+i].include?("** RESERVED **") || all[y+i-1].split('-')[1] != "2019"
  y = y + 1
end

#----------- nist ----------
for id in list
  url = "https://nvd.nist.gov/vuln/detail/CVE-2019-" + id
  doc = Nokogiri::HTML(open(url))
  
  impact=[]
  score = []
  cvss = []
  hyperlink = []
  description = []
  poc = []
  x=1
  
  doc.css('div#p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView_Vuln3CvssPanel p span').each do |link|
    impact << link.content
  end

  doc.css('div#p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView_VulnHyperlinksPanel table tr td').each do |link|
    hyperlink << link.content 
  end
  
  doc.css('table#p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView tr td div p').each do |link|
    description << link.content 
  end
  
  0.upto(hyperlink.count/2-1) do |i|
    if hyperlink[i+x].include?("Exploit") 
      poc <<  hyperlink[i+x-1]
    else
      poc << hyperlink[i+x-1] if hyperlink[i+x-1].include?("exploit")
    end
    x = x + 1
  end
 
  unless impact.empty?
    impact[2].split("(")[0].split('/').each do |z|
      cvss << z.split(':')[1]
    end
  end 
    
  unless poc.empty? || cvss.empty?
    cveid = id
    score = impact[0]
    puts cveid,description[0],score,cvss,poc
    puts "-------------"
  end 

end



