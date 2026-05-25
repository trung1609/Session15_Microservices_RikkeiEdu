package com.example.courseservice.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/courses")
public class CourseController {
    private List<String> courses = Arrays.asList(
            "Course 1: Introduction to Java",
            "Course 2: Spring Boot Basics",
            "Course 3: RESTful API Development",
            "Course 4: Microservices Architecture",
            "Course 5: Cloud Computing with AWS"
    );
    @GetMapping
    @PreAuthorize("hasAuthority('COURSE_READ')")
    public List<String> getAllCourses() {
        return courses;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('COURSE_WRITE')")
    public String addCourse() {
        return "Course added successfully";
    }
}
