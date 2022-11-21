package com.jang.mtg.service;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.jang.mtg.model.MrResTimeVO;
import com.jang.mtg.model.MrReserveVO;
import com.jang.mtg.model.MtRoomVO;
import com.jang.mtg.model.SearchVO;



public interface MtRoomService {

	
	
	List<MtRoomVO> Search_getMtRoomList(String searchKeyword); //?��록된 ?��?��?�� ?���? ?���?
	
	MtRoomVO getMtRoom(int mrNo); //?��?��?��?�� ?���?
	
	int insertMtRoom(MtRoomVO mtRoomVO); //?��?��?�� ?���?
	
	int updateMtRoom(MtRoomVO mtRoomVO); // ?��?��?�� ?��보수?��
	
	int deleteMtRoom(int mrNo); //?��?��?�� ?��록취?��
	
	List<MrReserveVO> getMrReserveList(MrResTimeVO mrResTimeVO1);// ?��별회?��?���? ?��?��목록 ?���?
	
	MrReserveVO getMrReserve(int reNo); //?��?�� ?��?�� ?���?
	
	int insertMrReserve(MrReserveVO mrReserveVO);//?��?�� ?���?
	
	int updateMrReserve(MrReserveVO mrReserveVO); //?��?�� ?��?��
	
	int deleteMrReserve(int reNo); //?��?��취소
	
	int resDupCeck(MrReserveVO mrReserveVO);//?��?�� 중복체크
	
	MrReserveVO getMrReserveByTime(MrReserveVO mrReserveVO); //?��?��?���? ?��?�� ?���?
	
	int getTotalRow(SearchVO searchVO);// ?��체�? ?�� 조회
	
	int getTotalRow2(SearchVO searchVO);// ?��체�? ?�� 조회
	
	
	StringBuffer getPageUrl(SearchVO searchvo);//?��?���?
	
	List<MtRoomVO> getMtRoomList(@Param(value = "startRow") int startRow, @Param(value = "endRow") int endRow);
	
	List<MtRoomVO> getMtRoomList(SearchVO searchVO); //?��록된 ?��?��?�� ?���? ?���?
}
