--這是Wireshark 台灣期交所TMP電文解析Plugin(LUA程式碼)
--作者： wldtw2008@gmail.com 2022-11-2
--使用方法：
--1. 編輯TMP.lua，拉到最下面，添加程式碼 tcp_encap_table:add(PVC通訊埠號,protoTMP)
--2. 打開Wireshark，點選工具列Help->About->Folders->GlobalPlugins(雙擊可以打開資料夾)，把這個TMP.lua放到這個資料夾
--3. 重啟Wireshark即可

do    
    local protoTMP = Proto.new("TMP", "Taifex Message Protocol")
    --宣告段
	local f_HdrMsgType = ProtoField.uint32("TMP.Type","Type",base.HEX,
	{[10]="L10", [20]="L20", [30]="L30",[40]="L40",[41]="L41",[50]="L50",[60]="L60",[101]="R01",[102]="R02",[103]="R03",[104]="R04",[105]="R05",[114]="R14",[122]="R22"
	})
	local f_HdrMsgLen = ProtoField.uint16("MsgLen","MsgLen",base.DEC)
	local f_HdrSeqNum = ProtoField.uint32("SeqNum","SeqNum",base.DEC)
	local f_TmpTimeEpoch = ProtoField.uint32("TS","TmpTime.Epoch",base.DEC) --時間戳 整數部分
	local f_TmpTimeMs= ProtoField.uint16("TS","TmpTime.Ms",base.DEC)        --時間戳 毫秒部分
	local f_FcmId = ProtoField.uint16("FcmId","FcmId",base.DEC)--期貨商編號
	local f_SessionId = ProtoField.uint16("SessionId","SessionId",base.DEC)--PVC Session ID
	
	local f_HeaderArea = ProtoField.bytes("Header")
	local f_BodyArea = ProtoField.bytes("Body")
	local f_ChkSumyByte = ProtoField.uint8("ChkSum", "ChkSum",base.HEX)
	
	local f_ExecType = ProtoField.uint8("ExecType","ExecType",base.HEX,
	{[string.byte('0')]="New", [string.byte('4')]="Cancel", [string.byte('5')]="DecressQty", [string.byte('M')]="ModifyPrc", [string.byte('m')]="ModifyPrc", [string.byte('I')]="Query"
	})
	
	local f_cmid = ProtoField.uint16("CmId","CmId",base.DEC)--結算會員編
	local f_OrderNo = ProtoField.string("OrderNo","OrderNo")--委託書號
	local f_OrdId = ProtoField.uint32("OrdId","OrdId",base.DEC)-- 委託書流水號	填委託單流水號(最多 7 碼數字)
	local f_UserDefine = ProtoField.bytes("UserDefine")--期貨商自訂變數 交易系統在新增刪單改量改價時，會自動更新此值到委託單狀態
	local f_SymbolType = ProtoField.uint8("SymbolType","SymbolType",base.DEC)--商品代號格式 R01(1: num, 2 : text)	R31(3: num, 4 : text)
	local f_SymbolID = ProtoField.string("SymbolID","SymbolID")--商品代號部份	x 部份可用 num	或 text 取代
	local f_Price = ProtoField.uint32("Price","Price",base.DEC)--委託價格 參考 委託價格
	local f_Qty = ProtoField.uint32("Qty","Qty",base.DEC)--委託口數
	local f_InvestorAcno = ProtoField.uint32("InvestorAcno","InvestorAcno",base.DEC)--交易人帳號
	local f_InvestorFlag=ProtoField.string("InvestorFlag","InvestorFlag")--投資人身份碼  1一般 2自營 8造市
	local f_Side = ProtoField.uint8("Side","Side",base.DEC, {[1]="Buy",[2]="Sell"})--買賣別 1:買, 2 : 賣 
	local f_OrdType = ProtoField.uint8("OrdType","OrdType",base.DEC, {[1]="Market",[2]="Limit",[3]="LimitMarket"})--委託方式 1 : Market, 2 : Limit, 3 :一定範圍市價委託
	local f_TimeInForce = ProtoField.uint8("TimeInForce","TimeInForce",base.DEC, {[4]="FOK",[3]="IOC",[0]="ROD",[8]="Quote"})--委託條件 FOK:4, IOC:3, ROD:0, 報價一定期間後系統自動刪除:8
	local f_PositionEffect=ProtoField.string("PositionEffec","PositionEffec")--開平倉碼 open : O(英文大寫),	close : C, daytrade : D	選擇權新倉含指定	部位沖銷 : A(Options Only)	代為沖銷 : 7
	local f_OrderSource=ProtoField.string("OrderSource","OrderSource")--char 委託類別註記	D : 專線下單(含VPN、封閉型專屬網路) A : API下單 M : 行動載具下單 W : 網站下單	P : 個人電腦軟體下單 V : 語音下單	G : 一般委託下單(書面、電話、電報等方式)
	local f_InfoSource=ProtoField.string("InfoSource","InfoSource")--行情資訊來源註記	1.由行情資訊廠商提供者，填入該行情資訊廠商代碼(詳行情資訊廠商代碼表註)。 2.由期貨商自行提供行情資訊者，填入“999”
	local f_StatusCode = ProtoField.uint8("StatusCod","StatusCod",base.DEC, {[0]="OK"})--狀態訊息碼正常填 0
	local f_LeavesQty = ProtoField.uint32("LeavesQty","LeavesQty",base.DEC)--現剩餘量
	local f_BeforeQty = ProtoField.uint32("BeforeQty","BeforeQty",base.DEC)--撮合前剩餘委託量
	local f_Leg1Prc = ProtoField.uint32("Leg1Prc","Leg1Prc",base.DEC)--兩邊商品成交價格
	local f_Leg1Qty = ProtoField.uint32("Leg1Qty","Leg1Qty",base.DEC)--兩邊商品成交口數
	local f_Leg2Prc = ProtoField.uint32("Leg2Prc","Leg2Prc",base.DEC)--兩邊商品成交價格
	local f_Leg2Qty = ProtoField.uint32("Leg2Qty","Leg2Qty",base.DEC)--兩邊商品成交口數
	local f_UniqId = ProtoField.uint32("UniqId","UniqId",base.DEC)--唯一序號	target_id = 4 則為系統唯一序號	(OrderID);target_id = 8, 9 則為回報序號(cm_sub_seq)
	local f_RptSeq = ProtoField.uint32("RptSeq","RptSeq",base.DEC)--回報序號target_id = 4 時為session 流水號(session_seq)  target_id = 8、9 時為結算會員回報序號(cm_seq)
	local f_ProtocolType = ProtoField.uint32("ProtocolType","ProtocolType",base.DEC, {[0]="Reserved",[1]="TMP",[2]="FIX"})--新單資料來源0：保留 1：TMP 2：FIX, 
	
    protoTMP.fields = {f_HdrMsgLen,f_HdrSeqNum,f_TmpTimeEpoch, f_TmpTimeMs, 
	f_HdrMsgType,  f_FcmId, f_SessionId,
	f_HeaderArea,  f_BodyArea, f_ChkSumyByte,
	f_ExecType,f_cmid,f_OrderNo	,f_OrdId,f_UserDefine,f_SymbolType,f_SymbolID,f_Price,f_Qty,f_InvestorAcno,f_InvestorFlag,f_Side,f_OrdType,f_TimeInForce,f_PositionEffect,f_OrderSource,f_InfoSource,
	f_StatusCode,f_LeavesQty,f_BeforeQty,f_Leg1Prc,f_Leg1Qty,f_Leg2Prc,f_Leg2Qty,f_UniqId,f_RptSeq,f_ProtocolType}

    --真正解析的部分
    local function check_and_dissector_TMP(buf,pkt,root)		
        local buf_len = buf:len();
        --封包長度太短就不是TMP
        if buf_len < 17 then return false end
		
		pkt.cols['protocol'] = "$$TMP"
		
		local msglen = buf(pkt.desegment_offset + 0,2):uint()
		local msgtype = buf(pkt.desegment_offset + 12,1):uint()
		local strMsgtype = "??("..msgtype..")"		
		
		--超過MTU被分割的TCP封包 用下面這個併起來
		if pkt.desegment_offset + msglen+3 > buf:len() then
			pkt.desegment_len = pkt.desegment_offset + msglen+3 - buf:len()
			return true
		end

		local t = root:add(protoTMP,buf)

		--Header
		local hdr = t:add(f_HeaderArea, buf(pkt.desegment_offset + 0, 17))
		hdr:add(f_HdrMsgLen, buf(pkt.desegment_offset + 0,2))
		hdr:add(f_HdrSeqNum, buf(pkt.desegment_offset + 2,4))
		hdr:add(f_TmpTimeEpoch, buf(pkt.desegment_offset + 6,4))
		hdr:add(f_TmpTimeMs, buf(pkt.desegment_offset + 10,2))
		hdr:add(f_HdrMsgType, buf(pkt.desegment_offset + 12,1))
		hdr:add(f_FcmId, buf(pkt.desegment_offset + 13, 2))
		hdr:add(f_SessionId, buf(pkt.desegment_offset + 15,2))

		--Body
		local bodyBegIdx = pkt.desegment_offset + 17
		local body = t:add(f_BodyArea, buf(bodyBegIdx, msglen+2-17))
		if (msgtype==10) then
			strMsgtype = "L10"
		elseif (msgtype==20) then
			strMsgtype = "L20"
		elseif (msgtype==30) then
			strMsgtype = "L30"
		elseif (msgtype==40) then
			strMsgtype = "L40"
		elseif (msgtype==41) then
			strMsgtype = "L41"
		elseif (msgtype==50) then
			strMsgtype = "L50"
		elseif (msgtype==60) then
			strMsgtype = "L60"
		elseif (msgtype==101) then					
			strMsgtype = "R01(??)"
			local execType = buf(bodyBegIdx+0,1):string()
			if (execType=="0") then
				strMsgtype = "R01(New)"
			elseif (execType=="4") then
				strMsgtype = "R01(Cancel)"
			elseif (execType=="5") then
				strMsgtype = "R01(DecressQty)"
			elseif (execType=="M") then
				strMsgtype = "R01(ModifyPrc:M)"
			elseif (execType=="m") then
				strMsgtype = "R01(ModifyPrc:m)"
			elseif (execType=="I") then
				strMsgtype = "R01(Query)"
			end
			body:add(f_ExecType, buf(bodyBegIdx+0,1))
			body:add(f_cmid, buf(bodyBegIdx+1,2))
			body:add(f_FcmId, buf(bodyBegIdx+3,2))
			body:add(f_OrderNo, buf(bodyBegIdx+5,5))
			body:add(f_OrdId, buf(bodyBegIdx+10,4))
			body:add(f_UserDefine, buf(bodyBegIdx+14,8))
			body:add(f_SymbolType, buf(bodyBegIdx+22,1))
			body:add(f_SymbolID, buf(bodyBegIdx+23,20))
			body:add(f_Price, buf(bodyBegIdx+43,4))
			body:add(f_Qty, buf(bodyBegIdx+47,2))
			body:add(f_InvestorAcno, buf(bodyBegIdx+49,4))
			body:add(f_InvestorFlag, buf(bodyBegIdx+53,1))
			body:add(f_Side, buf(bodyBegIdx+54,1))
			body:add(f_OrdType, buf(bodyBegIdx+55,1))
			body:add(f_TimeInForce, buf(bodyBegIdx+56,1))
			body:add(f_PositionEffect, buf(bodyBegIdx+57,1))
			body:add(f_OrderSource, buf(bodyBegIdx+58,1))
			body:add(f_InfoSource, buf(bodyBegIdx+59,3))
		elseif (msgtype==102) then
			strMsgtype = "R02(Reply Long)"
		elseif (msgtype==103) then
			strMsgtype = "R03(Error Order)"
			body:add(f_StatusCode, buf(bodyBegIdx+0,1))
			body:add(f_ExecType, buf(bodyBegIdx+1,1))
			body:add(f_FcmId, buf(bodyBegIdx+2,2))
			body:add(f_OrderNo, buf(bodyBegIdx+4,5))
			body:add(f_OrdId, buf(bodyBegIdx+9,4))
			body:add(f_UserDefine, buf(bodyBegIdx+13,8))
			body:add(f_RptSeq, buf(bodyBegIdx+21,4))
			body:add(f_Side, buf(bodyBegIdx+25,1))
		elseif (msgtype==104) then
			strMsgtype = "R04"
		elseif (msgtype==105) then
			strMsgtype = "R05"
		elseif (msgtype==114) then
			strMsgtype = "R14"
		elseif (msgtype==122) then
			strMsgtype = "R22(Reply Short)"
			body:add(f_StatusCode, buf(bodyBegIdx+0,1))
			body:add(f_ExecType, buf(bodyBegIdx+1,1))
			body:add(f_FcmId, buf(bodyBegIdx+2,2))
			body:add(f_OrderNo, buf(bodyBegIdx+4,5))
			body:add(f_OrdId, buf(bodyBegIdx+9,4))
			body:add(f_UserDefine, buf(bodyBegIdx+13,8))

			body:add(f_Side, buf(bodyBegIdx+21,1))
			body:add(f_PositionEffect, buf(bodyBegIdx+22,1))

			body:add(f_LeavesQty, buf(bodyBegIdx+23,2))
			body:add(f_BeforeQty, buf(bodyBegIdx+25,2))
			body:add(f_Leg1Prc, buf(bodyBegIdx+27,4))
			body:add(f_Leg2Prc, buf(bodyBegIdx+31,4))
			body:add(f_Leg1Qty, buf(bodyBegIdx+35,2))
			body:add(f_Leg2Qty, buf(bodyBegIdx+37,2))
			body:add(f_TmpTimeEpoch, buf(bodyBegIdx+39,4))
			body:add(f_TmpTimeMs, buf(bodyBegIdx+43,2))

			body:add(f_UniqId, buf(bodyBegIdx+45,4))
			body:add(f_RptSeq, buf(bodyBegIdx+49,4))
			body:add(f_ProtocolType, buf(bodyBegIdx+53,1))
			body:add(f_Price, buf(bodyBegIdx+54,4))
		end

		--CheckSum
		t:add(f_ChkSumyByte, buf(pkt.desegment_offset+msglen+2, 1))
		--下面這邊加總算CheckSum
		local sum = 0;		
		for i = pkt.desegment_offset,pkt.desegment_offset+msglen+2-1, 1 --for init,max/min value, increment
		do
			sum = (sum + (buf(i, 1):uint()))
		end
		local strCheck=string.format("   Sum = 0x%08x",sum)
		t:add(strCheck)
		
		if (pkt.desegment_offset == 0) then
			pkt.cols['info'] = "TMP"
		end
		pkt.cols['info']:append(" "..strMsgtype)
		
		--如果超過一個包 那就繼續遞迴下去解析
		if buf_len > pkt.desegment_offset + msglen+3 then
			pkt.desegment_offset = pkt.desegment_offset + msglen+3
			check_and_dissector_TMP(buf,pkt,root)
		end
			
        return true
    end
	
    function protoTMP.dissector(buf,pkt,root)
		local data_dis = Dissector.get("data")
        if check_and_dissector_TMP(buf,pkt,root) then
            --解析成功
        else
            --解析失敗，就不是TMP, 要往上層拋
            data_dis:call(buf,pkt,root)
        end
    end
    
    local tcp_encap_table = DissectorTable.get("tcp.port")
    --需要解析的PORT號在這裡添加
    tcp_encap_table:add(30210,protoTMP)
	tcp_encap_table:add(20244,protoTMP)
    tcp_encap_table:add(30205,protoTMP)
	tcp_encap_table:add(30001,protoTMP)
	tcp_encap_table:add(30002,protoTMP)
end