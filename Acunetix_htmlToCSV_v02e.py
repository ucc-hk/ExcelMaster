#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created in March 2019

@author: tb
correction pending:: 
-headers section adding into df 31 Mar 2019
-check error on next page issue
"""

''' 
Acunetix scan result html convert to csv 

Note:
1. To read files, use:
with open('filename') as f:
    lines = f.readlines()
'''

from bs4 import BeautifulSoup
import numpy as np
import pandas as pd
import sys

# html_file='ETV web.html'
html_file= sys.argv[1]
#usage to generate csv report: C:\Users\USER\Desktop\Assessment\_tools\Acunetix result converter > Py -3 Acunetix_htmlToCSV_v02e.py "Administration System.html"
with open(html_file) as f: 
    file_gf = f.readlines()

#print(type(file_gf), len(file_gf))
count=lastcountItm=lastcountItmD=num_Description=num_Impact=num_Recommendation=num_References=num_affectedItems=num_totalItems=num_DInf=num_reqhdrItems=num_totalreqhdr=num_rsphdrItems=num_totalrsphdr=0
key=0        
num=1
result_topic=Items=Finding=Severity=Description=Impact=Recommendation=References=''
Ref_class=AffI_class=ItemD_class=reqhdr_class=rsphdr_class=''
aftItem=Details=headerDetails=requestHeaders=responseHeaders=DetailedInfo=''
result_topic_list=errorClassLocator=[]

findingItemList=[]
findingItemDict={}
#df = pd.DataFrame(columns=['Ref','Findings','Abstract','Explanation', 'Recommendation', 'Issue_Summary','Engine_Breakdown', 'Package','Line','Risk','Issue_Details','Source_Details','Soc_Out','Sink_Details','Sink_Out'])
df = pd.DataFrame(columns=['Ref','Findings', 'Severity', 'Description','Impact', 'Recommendation', 'References', 'Affected_Items', 'Items_Details','Request_Headers' ,'Response_Headers','Detailed_Information'])


print(len(df))
hasScD=False

import re

#Insert finding record into DF
def insertDFrow():
    #Columns=['Ref','Findings','Description','Impact', 'Recommendation', 'References', 'Affected_items'*set limit to 1500 chars in excel cell, 'Headers_Details']    
#     df.loc[key-1]=[num-1, Finding, Severity, Description, Impact, Recommendation, References, aftItem, headerDetails, DetailedInfo] 
    df.loc[key]=[num-1, Finding, Severity, Description, Impact, Recommendation, References, aftItem, itemDetails, reqHdr, rspHdr, DetailedInfo]
    
# Return affected items title
def findingAffectedItems():
#    separator='\n'
#    items = separator.join([item.get('Items','n/a') for item in findingItemList])
#    print(findingItemList)
#    print(URL, findingItemList[-1].get('Items','-'))
    items = findingItemList[-1].get('Items','-')  #'-' is default value in case no key exist
#    print(type(items))
    return URL + items

# Return Items' details 
def findingItemDetails():
    fid = findingItemList[-1].get('Details','-')  #'-' is default value in case no key exist
#    print(len(fid))
    return (fid if len(fid) < 1500 else '...\n'+fid[:1500]+'\n...(Refer to original report for full details.)')

# Return either Request or Response header details 
def findingAffectedItemsHeaders(header):
#    return "\n" + Items + "\n" + requestHeaders[:1000]  + "\n" + responseHeaders[:1000]
    if header == 'Request':
        h = findingItemList[-1].get('Req_hdr','-')
        return (h if len(h) < 2000 else '...\n'+h[:2000]+'\n...(Refer to original report for full details.)')
    elif header == 'Response':
        h = findingItemList[-1].get('Rsp_hdr','-')
        return (h if len(h) < 2000 else '...\n'+h[:2000]+'\n...(Refer to original report for full details.)')  
        
def printDFcolumns():
    #Columns=['count','Ref', 'Description','Impact', 'Recommendation', 'References', 'Affected_items', 'Total_items', 'Detail info']
    print('Line:',count-12,'Ref:', num-1,'Dscp:', num_Description,'Impt:', num_Impact, 'Rec', num_Recommendation,'Ref' ,num_References,'Itm', num_affectedItems, 'totItm',num_totalItems, 'Dinfo',num_DInf)   

# Return HTML text section in single row
def HTMLtextSingleRow(row):
    return BeautifulSoup(file_gf[row].strip(),'lxml').get_text()

# Return HTML text section in multi rows
def HTMLtextMultiRow(row):
#    if BeautifulSoup(str(BeautifulSoup(file_gf[row].strip(),'lxml')).replace('<br/>','\n'),'lxml').get_text() == '':
#        print('null text')
#        row=row+2
    return BeautifulSoup(str(BeautifulSoup(file_gf[row].strip(),'lxml')).replace('<br/>','\n'),'lxml').get_text()

# Return scan target URL at the title page
def HTMLlink(row):
    return BeautifulSoup(file_gf[row].strip(),'lxml').a.get('href')

#append finding items to finding list
def appendFindingItemList():
#     findingItemDict.update(findingHeaderDict) #merge both dict as a item detail record
    findingItemList.append(findingItemDict) #add item details to item list and then reset value

# Return title class number
def HTMLsectionClassNum(row):
#     print(BeautifulSoup(file_gf[row].strip(),'lxml').find('td'))
    try: 
        return BeautifulSoup(file_gf[row].strip(),'lxml').find('td')['class'][0]
    except: 
        errorClassLocator.append('Class Locator Error @' + str(row) + ' @ '+ str(Finding) + ' @ '+ str(Items))
        errorClassLocator.append(BeautifulSoup(file_gf[row+3].strip(),'lxml'))
        errorClassLocator.append(BeautifulSoup(file_gf[row+13].strip(),'lxml'))
        return BeautifulSoup(file_gf[row+13].strip(),'lxml').find('td')['class'][0]   


for string in file_gf:
#        print(string.strip(), file_gf[count+2].strip())
    
    #check end of file_gf and add the last finding to the list
#    print(string)
    if count == len(file_gf)-1:
        result_topic_list.append(result_topic)
        appendFindingItemList()
        printDFcolumns()        
        #Details of Request and Response headers


        aftItem = findingAffectedItems()
        itemDetails = findingItemDetails()
        reqHdr = findingAffectedItemsHeaders('Request')
        rspHdr = findingAffectedItemsHeaders('Response')
#        print(aftItem)
        insertDFrow()

#######################################################################    
    #Locate scan target URL 
    if re.search('class="s4"', string):
#        print(count)
#        print(file_gf[count].strip())
        URL = HTMLtextSingleRow(count)+"\n\n"
    
#######################################################################
        #Locate Finding
    if string.find('>Severity</td>') >= 0:
        appendFindingItemList()
        printDFcolumns()

        #Details of Request and Response headers
        aftItem = findingAffectedItems()
        itemDetails = findingItemDetails()
        reqHdr = findingAffectedItemsHeaders('Request')
        rspHdr = findingAffectedItemsHeaders('Response')

        #add a finding record in DF 
        insertDFrow()

        result_topic += file_gf[count-12].strip()
#        findingItemList=[]
#        print(file_gf[count+1].strip())
#        result_topic += file_gf[count+1].strip()
        Finding = HTMLtextSingleRow(count-12)
        print('\n',num,Finding) 
        Severity=HTMLtextSingleRow(count).replace('Severity', '') 
#         print(Severity)
#         print(Description)    
#         print(f'\nResponse headers\n'+rsphdr_class+' '+responseHeaders[:100])

#     if re.search('class="s39"',string): #with wildcard expression

        #reset counts on reaching new finding section
        num_References=num_affectedItems=num_reqhdrItems=num_rsphdrItems=lastcountItm=lastcountItmD=0

        #reset value on reaching new finding section
        Items=Details=requestHeaders=responseHeaders=''
        result_topic=Description=Impact=Recommendation=headerDetails=DetailedInfo=References='' 
        result_topic_list.append(result_topic) #add finding to list and clear
#        num_SinkD=0
#        print()
        print('*****************************************')
#        print(count)
#        print(file_gf[count+9].strip())
#        result_topic += file_gf[count+9].strip()
        result_topic += file_gf[count].strip()

#        print(result_topic, num)
        num+=1
        key+=1

#######################################################################        
        #Description
    if string.find('>Description</td>') >= 0:
#    if re.search('class="s44"',string): #with wildcard expression
#        print(count)
#        print(file_gf[count+6].strip())
        num_Description+=1
        result_topic += file_gf[count+6].strip()
        Description+=HTMLtextMultiRow(count+6)        
#         print(Description)
        
#######################################################################   
       #Impact
    if string.find('>Impact</td>') >= 0:
#    if re.search('class="s44"',string): #with wildcard expression
#        print(count)
#        print(file_gf[count+6].strip())
        num_Impact+=1
        result_topic += file_gf[count+6].strip()
        Impact+=HTMLtextMultiRow(count+6)  

#######################################################################       
        #Recommendation
    if string.find('>Recommendation</td>') >= 0:
#    if re.search('class="s44"',string): #with wildcard expression
#        print(count)
#        print(file_gf[count+6].strip())
        num_Recommendation+=1
        result_topic += file_gf[count+6].strip()
        Recommendation+=HTMLtextMultiRow(count+6)
        
#######################################################################
        #References
    if string.find('>References</td>') >= 0 and Finding != '':
        References='' #reset References value when reach new References section
#         num_References=0
        #Reference section class number eg. s40
        if Ref_class == '':
            Ref_class=HTMLsectionClassNum(count+6)
#         print(Ref_class)

        #Locate References with class number
    if re.search('class="'+Ref_class+'"', string):
#        print(count)
        #Reference name and link
        References += HTMLtextSingleRow(count) + "\n" + HTMLlink(count) + "\n\n"
#         print(References)
        num_References+=1
        result_topic += file_gf[count].strip()
        
#######################################################################
        #Detailed Information
    if re.search('>Detailed information<',string):        
        num_DInf+=1
        DetailedInfo = "Refer to Follow-up Plan Details page report for more information."
#         print(DetailedInfo)
        
#######################################################################        
        #Affected Items
    if string.find('>Affected items</td>') >= 0 and Finding != '':
#         num_References=0
        #Affected items section class number eg. s41

        if AffI_class == '':
            AffI_class=HTMLsectionClassNum(count+6)
#         print('affItm '+str(count))
#         print(AffI_class)

        #Locate Affected items (from Alert details section) with class number
    if re.search('class="'+AffI_class+'"', string):
        
#        print(count)
#        print(file_gf[count].strip())
        num_affectedItems+=1
        num_totalItems+=1
        result_topic += file_gf[count].strip()
        
#        print(lastcountItm, count)
        if HTMLtextSingleRow(lastcountItm) != HTMLtextSingleRow(count): #check for repeat content
            Items += str(num_affectedItems)+') '+HTMLtextSingleRow(count)+'\n'
        
#        if HTMLtextMultiRow(lastcountItmD) != HTMLtextMultiRow(count+6):
#            Details += str(num_affectedItems)+'> '+HTMLtextMultiRow(count+6)+"\n\n"

#        print(Items)
        findingItemDict={'Items':Items}
        lastcountItm=count
#        lastcountItmD=count+6

#######################################################################
        #Items' Details
    if string.find('>Details</td>') >= 0 and Finding != '':
#         num_References=0
        #Affected items section class number eg. s41
        if ItemD_class == '':
#            print(HTMLsectionClassNum(count+3))
            ItemD_class=HTMLsectionClassNum(count+3)
#            print(ItemD_class)
    if re.search('class="'+ItemD_class+'"', string):
#        print(HTMLtextMultiRow(count))
        if HTMLtextMultiRow(lastcountItmD) != HTMLtextMultiRow(count):
            Details += str(num_affectedItems)+') '+HTMLtextMultiRow(count)+"\n\n"
        findingItemDict.update({'Details':Details})
        lastcountItmD=count
        
#######################################################################
#     #Request Headers
    if string.find('>Request headers</td>') >= 0:
#         print('reqhdr '+str(count))
        isReqHdr=True
        num_reqhdrItems+=1
        num_totalreqhdr+=1
        if reqhdr_class == '':
            reqhdr_class=HTMLsectionClassNum(count+3)
    if re.search('class="'+reqhdr_class+'"', string) and isReqHdr:
        requestHeaders += str(num_affectedItems)+') '+HTMLtextMultiRow(count)+"\n\n"
#        if 2<num<6: print(HTMLtextMultiRow(count+3), requestHeaders[:20]) #check if HTMLtextMultiRow return null in case of new page section
#        if num==4: print(HTMLtextMultiRow(count+3)[:80],'\n')
        findingItemDict.update({'Req_hdr':requestHeaders})
#         print('s50 @'+str(count))

#######################################################################     
#     #Response Headers   
    if string.find('>Response headers</td>') >= 0:
        isReqHdr=False
        num_rsphdrItems+=1
        num_totalrsphdr+=1
        if rsphdr_class == '':
            rsphdr_class=HTMLsectionClassNum(count+3)
##         print(f'ResHdr '+str(count)+' '+rsphdr_class)
    if re.search('class="'+rsphdr_class+'"', string) and not isReqHdr:
        responseHeaders += str(num_affectedItems)+') '+HTMLtextMultiRow(count)+"\n\n"
        findingItemDict.update({'Rsp_hdr':responseHeaders})
#######################################################################
    
    count += 1

#obsolete valuable result_topic_list !!
if result_topic_list[0] == '':
    result_topic_list.pop(0)

print('Ref_class:',Ref_class,'Itm_class:',AffI_class,'ItmD_class:',ItemD_class,'ReqHdr_class:',reqhdr_class,'RspHdr_class:',rsphdr_class)

#print(len(result_topic_list))
#print(Source_Details)
#print(df)
#for a in errorClassLocator: print(a)
df[1:].to_csv(html_file.replace('.html','')+'.csv')
#df.to_excel(html_file+'.xlsx')
# df[1:].to_csv(sys.argv[1].replace('.html','')+'.csv')